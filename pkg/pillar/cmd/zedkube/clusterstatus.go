// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func handleDNSCreate(ctxArg interface{}, _ string, statusArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	dns := statusArg.(types.DeviceNetworkStatus)
	applyDNS(ctx, dns)
}

func handleDNSModify(ctxArg interface{}, _ string, statusArg interface{}, _ interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	dns := statusArg.(types.DeviceNetworkStatus)
	applyDNS(ctx, dns)
}

func applyDNS(ctx *zedkubeContext, dns types.DeviceNetworkStatus) {
	ctx.deviceNetworkStatus = dns
	changed := updateClusterIPReadiness(ctx)
	if changed {
		if ctx.clusterIPIsReady {
			if ctx.statusServer == nil {
				startClusterStatusServer(ctx)
			}
		} else {
			if ctx.statusServer != nil {
				stopClusterStatusServer(ctx)
			}
		}
		// NIM can publish network status due to cluster config
		// removal, and we don't want to publish the dummy/empty
		// cluster status in that case.
		if ctx.clusterConfig.ClusterInterface != "" {
			publishKubeConfigStatus(ctx)
		}
	}
}

func applyClusterConfig(ctx *zedkubeContext, config, oldconfig *types.EdgeNodeClusterConfig) {
	noChange := reflect.DeepEqual(config, oldconfig)
	if noChange {
		log.Noticef("getKubeConfig: no change in cluster config")
		return
	}
	if config == nil {
		// Before we let NIM to remove the cluster IP, we need to remove the node
		// from the cluster.
		drainAndDeleteNode(ctx)
		stopClusterStatusServer(ctx)
		ctx.clusterConfig = types.EdgeNodeClusterConfig{}
		return
	} else {
		clusterIPChanged := !netutils.EqualIPNets(ctx.clusterConfig.ClusterIPPrefix,
			config.ClusterIPPrefix)
		ctx.clusterConfig = *config
		if clusterIPChanged {
			stopClusterStatusServer(ctx)
			updateClusterIPReadiness(ctx)
			if ctx.clusterIPIsReady {
				startClusterStatusServer(ctx)
			}
		}
	}
	publishKubeConfigStatus(ctx)
}

// publishKubeConfigStatus publishes the cluster config status
func publishKubeConfigStatus(ctx *zedkubeContext) {
	status := types.EdgeNodeClusterStatus{
		ClusterName:      ctx.clusterConfig.ClusterName,
		ClusterID:        ctx.clusterConfig.ClusterID,
		ClusterInterface: ctx.clusterConfig.ClusterInterface,
		ClusterIPPrefix:  ctx.clusterConfig.ClusterIPPrefix,
		ClusterIPIsReady: ctx.clusterIPIsReady,
		IsWorkerNode:     ctx.clusterConfig.IsWorkerNode,
		JoinServerIP:     ctx.clusterConfig.JoinServerIP,
		BootstrapNode:    ctx.clusterConfig.BootstrapNode,
	}

	// XXX temp configitem handling
	if ctx.clusterConfig.EncryptedClusterToken != "" {
		status.EncryptedClusterToken = ctx.clusterConfig.EncryptedClusterToken
		log.Noticef("publishKubeConfigStatus: use clearText token")
	} else if ctx.clusterConfig.CipherToken.IsCipher {
		decToken, err := decryptClusterToken(ctx)
		if err != nil {
			log.Errorf("publishKubeConfigStatus: failed to decrypt cluster token: %v", err)
			status.Error = types.ErrorDescription{
				Error:     err.Error(),
				ErrorTime: time.Now(),
			}
		} else {
			status.EncryptedClusterToken = decToken
			log.Noticef("publishKubeConfigStatus: use decrypted token")
		}
	} else {
		log.Errorf("publishKubeConfigStatus: cluster token is not from configitme or encrypted")
	}
	// publish the cluster status for the kube container
	ctx.pubEdgeNodeClusterStatus.Publish("global", status)
}

func decryptClusterToken(ctx *zedkubeContext) (string, error) {
	if !ctx.clusterConfig.CipherToken.IsCipher {
		return "", fmt.Errorf("decryptClusterToken: cluster token is not encrypted")
	}

	decryptAvailable := ctx.subControllerCert != nil && ctx.subEdgeNodeCert != nil
	if !decryptAvailable {
		return "", fmt.Errorf("decryptClusterToken: certificates are not available")
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  log,
			AgentName:            agentName,
			AgentMetrics:         ctx.cipherMetrics,
			PubSubControllerCert: ctx.subControllerCert,
			PubSubEdgeNodeCert:   ctx.subEdgeNodeCert,
		},
		ctx.clusterConfig.CipherToken)
	if ctx.pubCipherBlockStatus != nil {
		err2 := ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err2 != nil {
			return "", fmt.Errorf("decryptClusterToken: publish failed %v", err2)
		}
	}
	if err != nil {
		ctx.cipherMetrics.RecordFailure(log, types.DecryptFailed)
		return "", fmt.Errorf("decryptClusterToken: failed to decrypt cluster token: %v", err)
	}

	err = ctx.cipherMetrics.Publish(log, ctx.pubCipherMetrics, "global")
	if err != nil {
		log.Errorf("decryptClusterToken: publish failed for cipher metrics: %v", err)
		return "", fmt.Errorf("decryptClusterToken: failed to publish cipher metrics: %v", err)
	}

	return decBlock.ClusterToken, nil
}

func updateClusterIPReadiness(ctx *zedkubeContext) (changed bool) {
	var ready bool
	haveClusterIPConfig := ctx.clusterConfig.ClusterInterface != "" &&
		ctx.clusterConfig.ClusterIPPrefix != nil
	if haveClusterIPConfig {
		for _, port := range ctx.deviceNetworkStatus.Ports {
			if port.InvalidConfig || port.IfName == "" {
				continue
			}
			if port.Logicallabel != ctx.clusterConfig.ClusterInterface {
				continue
			}
			for _, addr := range port.AddrInfoList {
				if addr.Addr.Equal(ctx.clusterConfig.ClusterIPPrefix.IP) {
					ready = true
					break
				}
			}
			if ready {
				break
			}
		}
	}
	if ctx.clusterIPIsReady != ready {
		ctx.clusterIPIsReady = ready
		return true
	}
	return false
}

func startClusterStatusServer(ctx *zedkubeContext) {
	if ctx.statusServer != nil {
		// Already running.
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		clusterStatusHTTPHandler(w, r, ctx)
	})
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		appIDHandler(w, r, ctx)
	})

	mux.HandleFunc("/cluster-app/", func(w http.ResponseWriter, r *http.Request) {
		clusterAppIDHandler(w, r, ctx)
	})

	ctx.statusServer = &http.Server{
		Addr:    ctx.clusterConfig.ClusterIPPrefix.IP.String() + ":" + types.ClusterStatusPort,
		Handler: mux,
	}
	ctx.statusServerWG.Add(1)

	// Start the server in a goroutine
	go func() {
		defer ctx.statusServerWG.Done()
		if err := ctx.statusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Cluster status server ListenAndServe failed: %v", err)
		}
		log.Noticef("Cluster status server stopped")
	}()
}

func stopClusterStatusServer(ctx *zedkubeContext) {
	if ctx.statusServer == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ctx.statusServer.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Cluster status server shutdown failed: %v", err)
	} else {
		log.Noticef("Cluster status server shutdown completed")
	}

	// Wait for the server goroutine to finish
	ctx.statusServerWG.Wait()
	ctx.statusServer = nil
	log.Noticef("Cluster status server goroutine has stopped")
}

func clusterStatusHTTPHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get clientset %v", err)
		fmt.Fprint(w, "")
		return
	}

	err = getnodeNameAndUUID(ctx)
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: Error getting nodeName and nodeUUID")
		fmt.Fprint(w, "")
		return
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), ctx.nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("clusterStatusHTTPHandler: can't get node %v, for %s", err, ctx.nodeName)
		fmt.Fprint(w, "")
		return
	}

	var isMaster, isEtcd bool
	labels := node.GetLabels()
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		log.Noticef("clusterStatusHTTPHandler: master")
		isMaster = true
	}
	if _, ok := labels["node-role.kubernetes.io/etcd"]; ok {
		log.Noticef("clusterStatusHTTPHandler: etcd")
		isEtcd = true
	}

	if isMaster && isEtcd {
		log.Noticef("clusterStatusHTTPHandler: master and etcd")
		fmt.Fprint(w, "cluster")
		return
	}
	log.Noticef("clusterStatusHTTPHandler: not master or etcd")
	fmt.Fprint(w, "")
}

func appIDHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	// Extract the UUID from the URL
	uuidStr := strings.TrimPrefix(r.URL.Path, "/app/")
	if uuidStr == "" {
		http.Error(w, "UUID is required", http.StatusBadRequest)
		return
	}

	uuidStr, err := checkAppNameForUUID(ctx, uuidStr)
	if err != nil {
		http.Error(w, "App Name or UUID not found", http.StatusBadRequest)
		return
	}

	af := agentbase.GetApplicationInfo("/run/", "/persist/status/", uuidStr)
	if af.AppInfo == nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	appInfoJSON, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		http.Error(w, "Error marshalling appInfo to JSON", http.StatusInternalServerError)
		return
	}
	// Handle the request for the given UUID
	fmt.Fprintf(w, "%s", appInfoJSON)
	// Add your logic here to handle the request
}

func clusterAppIDHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	// Extract the UUID from the URL
	uuidStr := strings.TrimPrefix(r.URL.Path, "/cluster-app/")
	if uuidStr == "" {
		http.Error(w, "UUID is required", http.StatusBadRequest)
		return
	}

	uuidStr, err := checkAppNameForUUID(ctx, uuidStr)
	if err != nil {
		http.Error(w, "App Name or UUID not found", http.StatusBadRequest)
		return
	}

	af := agentbase.GetApplicationInfo("/run/", "/persist/status/", uuidStr)
	if af.AppInfo == nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	appInfoJSON, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		http.Error(w, "Error marshalling appInfo to JSON", http.StatusInternalServerError)
		return
	}

	// Initialize combined JSON with local app info
	combinedJSON := `{
  "key": "cluster-app",
  "value": [` + strings.TrimSuffix(string(appInfoJSON), "\n")

	hosts, notClusterMode, err := getClusterNodeIPs(ctx)
	if err == nil && !notClusterMode {
		for _, host := range hosts {
			req, err := http.NewRequest("POST", "http://"+host+":"+types.ClusterStatusPort+"/app/"+uuidStr, nil)
			if err != nil {
				log.Errorf("clusterAppIDHandler: %v", err)
				continue
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Errorf("clusterAppIDHandler: %v", err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Errorf("clusterAppIDHandler: received non-OK status %d from %s", resp.StatusCode, host)
				continue
			}

			remoteAppInfoJSON, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("clusterAppIDHandler: error reading response from %s: %v", host, err)
				continue
			}

			// Replace outermost { and } with [ and ] in remoteAppInfoJSON
			combinedJSON = combinedJSON + "," + strings.TrimSuffix(string(remoteAppInfoJSON), "\n")
		}
	}

	// Ensure the combined JSON is properly closed
	combinedJSON += "]\n}\n"

	// Return the combined JSON to the caller
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(combinedJSON))
}

func replaceOutermostBraces(jsonStr string) string {
	jsonStr = strings.TrimSpace(jsonStr)
	if len(jsonStr) > 0 && jsonStr[0] == '{' && jsonStr[len(jsonStr)-1] == '}' {
		jsonStr = "[" + jsonStr[1:len(jsonStr)-1] + "]"
	}
	return jsonStr
}

func checkAppNameForUUID(ctx *zedkubeContext, appStr string) (string, error) {
	// Verify the extracted UUID string
	if _, err := uuid.FromString(appStr); err != nil {
		// then check if this is the app Name
		sub := ctx.subAppInstanceConfig
		items := sub.GetAll()
		if len(items) == 0 {
			return "", fmt.Errorf("App not found")
		}
		var foundApp bool
		for _, item := range items {
			aiconfig := item.(types.AppInstanceConfig)
			if aiconfig.DisplayName == appStr {
				appStr = aiconfig.UUIDandVersion.UUID.String()
				foundApp = true
				break
			}
		}
		if !foundApp {
			return "", fmt.Errorf("App not found")
		}
	}
	return appStr, nil
}

func getClusterNodeIPs(ctx *zedkubeContext) ([]string, bool, error) {
	if !ctx.clusterIPIsReady || !ctx.allowClusterPubSub {
		return nil, true, nil
	}

	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("getClusterNodes: config is nil")
		return nil, false, err
	}
	ctx.config = config

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return nil, false, err
	}

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("Error getting cluster nodes")
		return nil, false, err
	}

	// get all the nodes internal ip addresses except for my own
	clusterIPStr := ctx.clusterConfig.ClusterIPPrefix.IP.String()
	var hosts []string
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP && addr.Address != clusterIPStr {
				hosts = append(hosts, addr.Address)
			}
		}
	}
	return hosts, false, nil
}

package kubeapi

import (
	"context"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/base"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateNAD : create a new NAD (NetworkAttachmentDefinition).
func CreateNAD(log *base.LogObject, nadName, jsonSpec string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("CreateNAD: Failed to create netclientset: %v", err)
		return err
	}
	nad := &netattdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: nadName,
		},
		Spec: netattdefv1.NetworkAttachmentDefinitionSpec{
			Config: jsonSpec,
		},
	}
	createdNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVENamespace).
		Create(context.Background(), nad, metav1.CreateOptions{})
	if err == nil {
		log.Noticef("CreateNAD: successfully created NAD %s: %+v", nadName, createdNAD)
	} else {
		log.Errorf("CreateNAD: failed to create NAD %s: %v", nadName, err)
	}
	return err
}

// UpdateNAD : update specification of the given NAD (NetworkAttachmentDefinition).
func UpdateNAD(log *base.LogObject, nadName, jsonSpec string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("UpdateNAD: Failed to create netclientset: %v", err)
		return err
	}
	nad := &netattdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: nadName,
		},
		Spec: netattdefv1.NetworkAttachmentDefinitionSpec{
			Config: jsonSpec,
		},
	}
	createdNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVENamespace).
		Update(context.Background(), nad, metav1.UpdateOptions{})
	if err == nil {
		log.Noticef("UpdateNAD: successfully updated NAD %s: %+v", nadName, createdNAD)
	} else {
		log.Errorf("UpdateNAD: failed to update NAD %s: %v", nadName, err)
	}
	return err
}

// DeleteNAD : delete NAD with the given name (NetworkAttachmentDefinition).
func DeleteNAD(log *base.LogObject, nadName string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("DeleteNAD: Failed to create netclientset: %v", err)
		return err
	}
	err = netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVENamespace).
		Delete(context.Background(), nadName, metav1.DeleteOptions{})
	if err == nil {
		log.Noticef("DeleteNAD: successfully deleted NAD %s", nadName)
	} else {
		log.Errorf("DeleteNAD: failed to delete NAD %s: %v", nadName, err)
	}
	return err
}

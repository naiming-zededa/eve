// Copyright(c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.23.4
// source: nestedappinstancemetrics/nestedappinstancemetrics.proto

package nestedappinstancemetrics

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// NestedAppMetrics object to serve as a metric
// for a top level appinstance and all containers
// inside an app instance.  A single parent NestedAppMetrics returned from
// GET /api/v1/metrics/nested-app-id/<app-id>
// This structure is protojson marshaled and unmarshaled, field case cannot change.
type NestedAppMetrics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The parent NestedAppMetrics.Id will have an app instance uuid
	// to show app level metrics where the app is a group of one or more containers.
	// The child_container_metrics NestedAppMetrics.Id will have a container id
	// where the prefix matches the parent id.
	Id     string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Status string `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"` // uptime, pause, stop status
	Pids   uint32 `protobuf:"varint,3,opt,name=Pids,proto3" json:"Pids,omitempty"`    // number of PIDs within the container
	// CPU stats
	Uptime         int64  `protobuf:"varint,4,opt,name=uptime,proto3" json:"uptime,omitempty"`                 // unix.nano, time since container starts
	CPUTotal       uint64 `protobuf:"varint,5,opt,name=CPUTotal,proto3" json:"CPUTotal,omitempty"`             // container CPU since starts in nanosec
	SystemCPUTotal uint64 `protobuf:"varint,6,opt,name=SystemCPUTotal,proto3" json:"SystemCPUTotal,omitempty"` // total system, user, idle in nanosec
	// Memory stats
	UsedMem      uint32 `protobuf:"varint,7,opt,name=UsedMem,proto3" json:"UsedMem,omitempty"`           // in MBytes
	AllocatedMem uint32 `protobuf:"varint,8,opt,name=AllocatedMem,proto3" json:"AllocatedMem,omitempty"` // in MBytes
	// Network stats
	TxBytes uint64 `protobuf:"varint,9,opt,name=TxBytes,proto3" json:"TxBytes,omitempty"`  // in Bytes
	RxBytes uint64 `protobuf:"varint,10,opt,name=RxBytes,proto3" json:"RxBytes,omitempty"` // in Bytes
	// Disk stats
	ReadBytes  uint64 `protobuf:"varint,11,opt,name=ReadBytes,proto3" json:"ReadBytes,omitempty"`   // in MBytes
	WriteBytes uint64 `protobuf:"varint,12,opt,name=WriteBytes,proto3" json:"WriteBytes,omitempty"` // in MBytes
	// Child container metrics
	// id field should be a container name where the prefix
	// is the app instance id / above parent id.
	// For a compose app these id fields will be '<appid>-<service>-<replica>'
	ChildContainerMetrics []*NestedAppMetrics `protobuf:"bytes,13,rep,name=child_container_metrics,json=childContainerMetrics,proto3" json:"child_container_metrics,omitempty"`
}

func (x *NestedAppMetrics) Reset() {
	*x = NestedAppMetrics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nestedappinstancemetrics_nestedappinstancemetrics_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NestedAppMetrics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NestedAppMetrics) ProtoMessage() {}

func (x *NestedAppMetrics) ProtoReflect() protoreflect.Message {
	mi := &file_nestedappinstancemetrics_nestedappinstancemetrics_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NestedAppMetrics.ProtoReflect.Descriptor instead.
func (*NestedAppMetrics) Descriptor() ([]byte, []int) {
	return file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescGZIP(), []int{0}
}

func (x *NestedAppMetrics) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *NestedAppMetrics) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *NestedAppMetrics) GetPids() uint32 {
	if x != nil {
		return x.Pids
	}
	return 0
}

func (x *NestedAppMetrics) GetUptime() int64 {
	if x != nil {
		return x.Uptime
	}
	return 0
}

func (x *NestedAppMetrics) GetCPUTotal() uint64 {
	if x != nil {
		return x.CPUTotal
	}
	return 0
}

func (x *NestedAppMetrics) GetSystemCPUTotal() uint64 {
	if x != nil {
		return x.SystemCPUTotal
	}
	return 0
}

func (x *NestedAppMetrics) GetUsedMem() uint32 {
	if x != nil {
		return x.UsedMem
	}
	return 0
}

func (x *NestedAppMetrics) GetAllocatedMem() uint32 {
	if x != nil {
		return x.AllocatedMem
	}
	return 0
}

func (x *NestedAppMetrics) GetTxBytes() uint64 {
	if x != nil {
		return x.TxBytes
	}
	return 0
}

func (x *NestedAppMetrics) GetRxBytes() uint64 {
	if x != nil {
		return x.RxBytes
	}
	return 0
}

func (x *NestedAppMetrics) GetReadBytes() uint64 {
	if x != nil {
		return x.ReadBytes
	}
	return 0
}

func (x *NestedAppMetrics) GetWriteBytes() uint64 {
	if x != nil {
		return x.WriteBytes
	}
	return 0
}

func (x *NestedAppMetrics) GetChildContainerMetrics() []*NestedAppMetrics {
	if x != nil {
		return x.ChildContainerMetrics
	}
	return nil
}

var File_nestedappinstancemetrics_nestedappinstancemetrics_proto protoreflect.FileDescriptor

var file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDesc = []byte{
	0x0a, 0x37, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x73, 0x74, 0x61,
	0x6e, 0x63, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x2f, 0x6e, 0x65, 0x73, 0x74, 0x65,
	0x64, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x74, 0x72,
	0x69, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x6f, 0x72, 0x67, 0x2e, 0x6c,
	0x66, 0x65, 0x64, 0x67, 0x65, 0x2e, 0x65, 0x76, 0x65, 0x2e, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64,
	0x61, 0x70, 0x70, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x73, 0x22, 0xcd, 0x03, 0x0a, 0x10, 0x4e, 0x65, 0x73, 0x74, 0x65, 0x64, 0x41, 0x70, 0x70,
	0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x50, 0x69, 0x64, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x50,
	0x69, 0x64, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x75, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x06, 0x75, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x43,
	0x50, 0x55, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x43,
	0x50, 0x55, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x26, 0x0a, 0x0e, 0x53, 0x79, 0x73, 0x74, 0x65,
	0x6d, 0x43, 0x50, 0x55, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0e, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x43, 0x50, 0x55, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12,
	0x18, 0x0a, 0x07, 0x55, 0x73, 0x65, 0x64, 0x4d, 0x65, 0x6d, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x55, 0x73, 0x65, 0x64, 0x4d, 0x65, 0x6d, 0x12, 0x22, 0x0a, 0x0c, 0x41, 0x6c, 0x6c,
	0x6f, 0x63, 0x61, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x6d, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x6d, 0x12, 0x18, 0x0a,
	0x07, 0x54, 0x78, 0x42, 0x79, 0x74, 0x65, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07,
	0x54, 0x78, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x52, 0x78, 0x42, 0x79, 0x74,
	0x65, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x52, 0x78, 0x42, 0x79, 0x74, 0x65,
	0x73, 0x12, 0x1c, 0x0a, 0x09, 0x52, 0x65, 0x61, 0x64, 0x42, 0x79, 0x74, 0x65, 0x73, 0x18, 0x0b,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x52, 0x65, 0x61, 0x64, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12,
	0x1e, 0x0a, 0x0a, 0x57, 0x72, 0x69, 0x74, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0a, 0x57, 0x72, 0x69, 0x74, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12,
	0x71, 0x0a, 0x17, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x5f, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x39, 0x2e, 0x6f, 0x72, 0x67, 0x2e, 0x6c, 0x66, 0x65, 0x64, 0x67, 0x65, 0x2e, 0x65, 0x76,
	0x65, 0x2e, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x73, 0x74, 0x61,
	0x6e, 0x63, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x2e, 0x4e, 0x65, 0x73, 0x74, 0x65,
	0x64, 0x41, 0x70, 0x70, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x15, 0x63, 0x68, 0x69,
	0x6c, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x73, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6c, 0x66, 0x2d, 0x65, 0x64, 0x67, 0x65, 0x2f, 0x65, 0x76, 0x65, 0x2d, 0x61, 0x70, 0x69,
	0x2f, 0x67, 0x6f, 0x2f, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x73,
	0x74, 0x61, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescOnce sync.Once
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescData = file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDesc
)

func file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescGZIP() []byte {
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescOnce.Do(func() {
		file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescData = protoimpl.X.CompressGZIP(file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescData)
	})
	return file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDescData
}

var file_nestedappinstancemetrics_nestedappinstancemetrics_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_nestedappinstancemetrics_nestedappinstancemetrics_proto_goTypes = []interface{}{
	(*NestedAppMetrics)(nil), // 0: org.lfedge.eve.nestedappinstancemetrics.NestedAppMetrics
}
var file_nestedappinstancemetrics_nestedappinstancemetrics_proto_depIdxs = []int32{
	0, // 0: org.lfedge.eve.nestedappinstancemetrics.NestedAppMetrics.child_container_metrics:type_name -> org.lfedge.eve.nestedappinstancemetrics.NestedAppMetrics
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_nestedappinstancemetrics_nestedappinstancemetrics_proto_init() }
func file_nestedappinstancemetrics_nestedappinstancemetrics_proto_init() {
	if File_nestedappinstancemetrics_nestedappinstancemetrics_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nestedappinstancemetrics_nestedappinstancemetrics_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NestedAppMetrics); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_nestedappinstancemetrics_nestedappinstancemetrics_proto_goTypes,
		DependencyIndexes: file_nestedappinstancemetrics_nestedappinstancemetrics_proto_depIdxs,
		MessageInfos:      file_nestedappinstancemetrics_nestedappinstancemetrics_proto_msgTypes,
	}.Build()
	File_nestedappinstancemetrics_nestedappinstancemetrics_proto = out.File
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_rawDesc = nil
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_goTypes = nil
	file_nestedappinstancemetrics_nestedappinstancemetrics_proto_depIdxs = nil
}

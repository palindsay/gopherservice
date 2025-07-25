// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v6.31.1
// source: api/v1/petstore.proto

package v1

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Pet represents a pet in the pet store.
type Pet struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The unique identifier for the pet.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The name of the pet.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// The species of the pet.
	Species string `protobuf:"bytes,3,opt,name=species,proto3" json:"species,omitempty"`
	// The birth date of the pet.
	BirthDate     *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=birth_date,json=birthDate,proto3" json:"birth_date,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Pet) Reset() {
	*x = Pet{}
	mi := &file_api_v1_petstore_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Pet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Pet) ProtoMessage() {}

func (x *Pet) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Pet.ProtoReflect.Descriptor instead.
func (*Pet) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{0}
}

func (x *Pet) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Pet) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Pet) GetSpecies() string {
	if x != nil {
		return x.Species
	}
	return ""
}

func (x *Pet) GetBirthDate() *timestamppb.Timestamp {
	if x != nil {
		return x.BirthDate
	}
	return nil
}

// Order represents an order for a pet.
type Order struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The unique identifier for the order.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The ID of the pet being ordered.
	PetId string `protobuf:"bytes,2,opt,name=pet_id,json=petId,proto3" json:"pet_id,omitempty"`
	// The quantity of pets being ordered.
	Quantity int32 `protobuf:"varint,3,opt,name=quantity,proto3" json:"quantity,omitempty"`
	// The date the order was placed.
	OrderDate     *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=order_date,json=orderDate,proto3" json:"order_date,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Order) Reset() {
	*x = Order{}
	mi := &file_api_v1_petstore_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Order) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Order) ProtoMessage() {}

func (x *Order) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Order.ProtoReflect.Descriptor instead.
func (*Order) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{1}
}

func (x *Order) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Order) GetPetId() string {
	if x != nil {
		return x.PetId
	}
	return ""
}

func (x *Order) GetQuantity() int32 {
	if x != nil {
		return x.Quantity
	}
	return 0
}

func (x *Order) GetOrderDate() *timestamppb.Timestamp {
	if x != nil {
		return x.OrderDate
	}
	return nil
}

// CreatePetRequest is the request to create a new pet.
type CreatePetRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The pet to create. The ID field will be ignored if provided.
	Pet           *Pet `protobuf:"bytes,1,opt,name=pet,proto3" json:"pet,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CreatePetRequest) Reset() {
	*x = CreatePetRequest{}
	mi := &file_api_v1_petstore_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreatePetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreatePetRequest) ProtoMessage() {}

func (x *CreatePetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreatePetRequest.ProtoReflect.Descriptor instead.
func (*CreatePetRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{2}
}

func (x *CreatePetRequest) GetPet() *Pet {
	if x != nil {
		return x.Pet
	}
	return nil
}

// CreatePetResponse is the response after creating a new pet.
type CreatePetResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The created pet.
	Pet           *Pet `protobuf:"bytes,1,opt,name=pet,proto3" json:"pet,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CreatePetResponse) Reset() {
	*x = CreatePetResponse{}
	mi := &file_api_v1_petstore_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreatePetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreatePetResponse) ProtoMessage() {}

func (x *CreatePetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreatePetResponse.ProtoReflect.Descriptor instead.
func (*CreatePetResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{3}
}

func (x *CreatePetResponse) GetPet() *Pet {
	if x != nil {
		return x.Pet
	}
	return nil
}

// GetPetRequest is the request to get a pet by its ID.
type GetPetRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The ID of the pet to retrieve.
	Id            string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPetRequest) Reset() {
	*x = GetPetRequest{}
	mi := &file_api_v1_petstore_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPetRequest) ProtoMessage() {}

func (x *GetPetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPetRequest.ProtoReflect.Descriptor instead.
func (*GetPetRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{4}
}

func (x *GetPetRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// GetPetResponse is the response containing the pet.
type GetPetResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The retrieved pet.
	Pet           *Pet `protobuf:"bytes,1,opt,name=pet,proto3" json:"pet,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPetResponse) Reset() {
	*x = GetPetResponse{}
	mi := &file_api_v1_petstore_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPetResponse) ProtoMessage() {}

func (x *GetPetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPetResponse.ProtoReflect.Descriptor instead.
func (*GetPetResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{5}
}

func (x *GetPetResponse) GetPet() *Pet {
	if x != nil {
		return x.Pet
	}
	return nil
}

// PlaceOrderRequest is the request to place an order for a pet.
type PlaceOrderRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The order to place.
	Order         *Order `protobuf:"bytes,1,opt,name=order,proto3" json:"order,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PlaceOrderRequest) Reset() {
	*x = PlaceOrderRequest{}
	mi := &file_api_v1_petstore_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PlaceOrderRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlaceOrderRequest) ProtoMessage() {}

func (x *PlaceOrderRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlaceOrderRequest.ProtoReflect.Descriptor instead.
func (*PlaceOrderRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{6}
}

func (x *PlaceOrderRequest) GetOrder() *Order {
	if x != nil {
		return x.Order
	}
	return nil
}

// PlaceOrderResponse is the response after placing an order.
type PlaceOrderResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The placed order.
	Order         *Order `protobuf:"bytes,1,opt,name=order,proto3" json:"order,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PlaceOrderResponse) Reset() {
	*x = PlaceOrderResponse{}
	mi := &file_api_v1_petstore_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PlaceOrderResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlaceOrderResponse) ProtoMessage() {}

func (x *PlaceOrderResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlaceOrderResponse.ProtoReflect.Descriptor instead.
func (*PlaceOrderResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{7}
}

func (x *PlaceOrderResponse) GetOrder() *Order {
	if x != nil {
		return x.Order
	}
	return nil
}

// GetOrderRequest is the request to get an order by its ID.
type GetOrderRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The ID of the order to retrieve.
	Id            string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetOrderRequest) Reset() {
	*x = GetOrderRequest{}
	mi := &file_api_v1_petstore_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetOrderRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOrderRequest) ProtoMessage() {}

func (x *GetOrderRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOrderRequest.ProtoReflect.Descriptor instead.
func (*GetOrderRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{8}
}

func (x *GetOrderRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// GetOrderResponse is the response containing the order.
type GetOrderResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The retrieved order.
	Order         *Order `protobuf:"bytes,1,opt,name=order,proto3" json:"order,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetOrderResponse) Reset() {
	*x = GetOrderResponse{}
	mi := &file_api_v1_petstore_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetOrderResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetOrderResponse) ProtoMessage() {}

func (x *GetOrderResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_petstore_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetOrderResponse.ProtoReflect.Descriptor instead.
func (*GetOrderResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_petstore_proto_rawDescGZIP(), []int{9}
}

func (x *GetOrderResponse) GetOrder() *Order {
	if x != nil {
		return x.Order
	}
	return nil
}

var File_api_v1_petstore_proto protoreflect.FileDescriptor

const file_api_v1_petstore_proto_rawDesc = "" +
	"\n" +
	"\x15api/v1/petstore.proto\x12\x02v1\x1a\x1cgoogle/api/annotations.proto\x1a\x1fgoogle/protobuf/timestamp.proto\"~\n" +
	"\x03Pet\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\x12\x18\n" +
	"\aspecies\x18\x03 \x01(\tR\aspecies\x129\n" +
	"\n" +
	"birth_date\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampR\tbirthDate\"\x85\x01\n" +
	"\x05Order\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12\x15\n" +
	"\x06pet_id\x18\x02 \x01(\tR\x05petId\x12\x1a\n" +
	"\bquantity\x18\x03 \x01(\x05R\bquantity\x129\n" +
	"\n" +
	"order_date\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampR\torderDate\"-\n" +
	"\x10CreatePetRequest\x12\x19\n" +
	"\x03pet\x18\x01 \x01(\v2\a.v1.PetR\x03pet\".\n" +
	"\x11CreatePetResponse\x12\x19\n" +
	"\x03pet\x18\x01 \x01(\v2\a.v1.PetR\x03pet\"\x1f\n" +
	"\rGetPetRequest\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\"+\n" +
	"\x0eGetPetResponse\x12\x19\n" +
	"\x03pet\x18\x01 \x01(\v2\a.v1.PetR\x03pet\"4\n" +
	"\x11PlaceOrderRequest\x12\x1f\n" +
	"\x05order\x18\x01 \x01(\v2\t.v1.OrderR\x05order\"5\n" +
	"\x12PlaceOrderResponse\x12\x1f\n" +
	"\x05order\x18\x01 \x01(\v2\t.v1.OrderR\x05order\"!\n" +
	"\x0fGetOrderRequest\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\"3\n" +
	"\x10GetOrderResponse\x12\x1f\n" +
	"\x05order\x18\x01 \x01(\v2\t.v1.OrderR\x05order2\xcc\x02\n" +
	"\x0fPetStoreService\x12M\n" +
	"\tCreatePet\x12\x14.v1.CreatePetRequest\x1a\x15.v1.CreatePetResponse\"\x13\x82\xd3\xe4\x93\x02\r:\x01*\"\b/v1/pets\x12F\n" +
	"\x06GetPet\x12\x11.v1.GetPetRequest\x1a\x12.v1.GetPetResponse\"\x15\x82\xd3\xe4\x93\x02\x0f\x12\r/v1/pets/{id}\x12R\n" +
	"\n" +
	"PlaceOrder\x12\x15.v1.PlaceOrderRequest\x1a\x16.v1.PlaceOrderResponse\"\x15\x82\xd3\xe4\x93\x02\x0f:\x01*\"\n" +
	"/v1/orders\x12N\n" +
	"\bGetOrder\x12\x13.v1.GetOrderRequest\x1a\x14.v1.GetOrderResponse\"\x17\x82\xd3\xe4\x93\x02\x11\x12\x0f/v1/orders/{id}B*Z(github.com/plindsay/gopherservice/api/v1b\x06proto3"

var (
	file_api_v1_petstore_proto_rawDescOnce sync.Once
	file_api_v1_petstore_proto_rawDescData []byte
)

func file_api_v1_petstore_proto_rawDescGZIP() []byte {
	file_api_v1_petstore_proto_rawDescOnce.Do(func() {
		file_api_v1_petstore_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_api_v1_petstore_proto_rawDesc), len(file_api_v1_petstore_proto_rawDesc)))
	})
	return file_api_v1_petstore_proto_rawDescData
}

var file_api_v1_petstore_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_api_v1_petstore_proto_goTypes = []any{
	(*Pet)(nil),                   // 0: v1.Pet
	(*Order)(nil),                 // 1: v1.Order
	(*CreatePetRequest)(nil),      // 2: v1.CreatePetRequest
	(*CreatePetResponse)(nil),     // 3: v1.CreatePetResponse
	(*GetPetRequest)(nil),         // 4: v1.GetPetRequest
	(*GetPetResponse)(nil),        // 5: v1.GetPetResponse
	(*PlaceOrderRequest)(nil),     // 6: v1.PlaceOrderRequest
	(*PlaceOrderResponse)(nil),    // 7: v1.PlaceOrderResponse
	(*GetOrderRequest)(nil),       // 8: v1.GetOrderRequest
	(*GetOrderResponse)(nil),      // 9: v1.GetOrderResponse
	(*timestamppb.Timestamp)(nil), // 10: google.protobuf.Timestamp
}
var file_api_v1_petstore_proto_depIdxs = []int32{
	10, // 0: v1.Pet.birth_date:type_name -> google.protobuf.Timestamp
	10, // 1: v1.Order.order_date:type_name -> google.protobuf.Timestamp
	0,  // 2: v1.CreatePetRequest.pet:type_name -> v1.Pet
	0,  // 3: v1.CreatePetResponse.pet:type_name -> v1.Pet
	0,  // 4: v1.GetPetResponse.pet:type_name -> v1.Pet
	1,  // 5: v1.PlaceOrderRequest.order:type_name -> v1.Order
	1,  // 6: v1.PlaceOrderResponse.order:type_name -> v1.Order
	1,  // 7: v1.GetOrderResponse.order:type_name -> v1.Order
	2,  // 8: v1.PetStoreService.CreatePet:input_type -> v1.CreatePetRequest
	4,  // 9: v1.PetStoreService.GetPet:input_type -> v1.GetPetRequest
	6,  // 10: v1.PetStoreService.PlaceOrder:input_type -> v1.PlaceOrderRequest
	8,  // 11: v1.PetStoreService.GetOrder:input_type -> v1.GetOrderRequest
	3,  // 12: v1.PetStoreService.CreatePet:output_type -> v1.CreatePetResponse
	5,  // 13: v1.PetStoreService.GetPet:output_type -> v1.GetPetResponse
	7,  // 14: v1.PetStoreService.PlaceOrder:output_type -> v1.PlaceOrderResponse
	9,  // 15: v1.PetStoreService.GetOrder:output_type -> v1.GetOrderResponse
	12, // [12:16] is the sub-list for method output_type
	8,  // [8:12] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_api_v1_petstore_proto_init() }
func file_api_v1_petstore_proto_init() {
	if File_api_v1_petstore_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_api_v1_petstore_proto_rawDesc), len(file_api_v1_petstore_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1_petstore_proto_goTypes,
		DependencyIndexes: file_api_v1_petstore_proto_depIdxs,
		MessageInfos:      file_api_v1_petstore_proto_msgTypes,
	}.Build()
	File_api_v1_petstore_proto = out.File
	file_api_v1_petstore_proto_goTypes = nil
	file_api_v1_petstore_proto_depIdxs = nil
}

#ifndef YARA_CC
#define YARA_CC

#include <stdio.h>
#include <string.h>
#include "yara.h"

const char* yara_strerror(int code) {
	return strerror(code);
}

namespace yara {

static Nan::Persistent<FunctionTemplate> ScannerWrap_constructor;

void InitAll(Handle<Object> exports) {
	ExportConstants(exports);

	ScannerWrap::Init(exports);
}

NODE_MODULE(yara, InitAll)

void ExportConstants(Handle<Object> target) {
	Local<Object> error_codes = Nan::New<Object>();

	Nan::Set(target, Nan::New("Errorcodes").ToLocalChecked(), error_codes);

	Nan::Set(error_codes, Nan::New("ERROR_SUCCESS").ToLocalChecked(), Nan::New<Number>(0));
}

void ScannerWrap::Init(Handle<Object> exports) {
	Nan::HandleScope scope;

	Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(ScannerWrap::New);
	tpl->SetClassName(Nan::New("ScannerWrap").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "destroy", Destroy);

	ScannerWrap_constructor.Reset(tpl);
	exports->Set(Nan::New("ScannerWrap").ToLocalChecked(),
			Nan::GetFunction(tpl).ToLocalChecked());
}

ScannerWrap::ScannerWrap() {}

ScannerWrap::~ScannerWrap() {}

NAN_METHOD(ScannerWrap::Destroy) {
	Nan::HandleScope scope;
	
	ScannerWrap* scanner = ScannerWrap::Unwrap<ScannerWrap>(info.This());
	
	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ScannerWrap::New) {
	Nan::HandleScope scope;
	
	ScannerWrap* scanner = new ScannerWrap();
	
	scanner->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

}; /* namespace yara */

#endif /* YARA_CC */

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
	Local<Object> error_code = Nan::New<Object>();

	Nan::Set(target, Nan::New("ErrorCode").ToLocalChecked(), error_code);

	Nan::Set(error_code, Nan::New("ERROR_SUCCESS").ToLocalChecked(), Nan::New<Number>(ERROR_SUCCESS));
	Nan::Set(error_code, Nan::New("ERROR_INSUFICIENT_MEMORY").ToLocalChecked(), Nan::New<Number>(ERROR_INSUFICIENT_MEMORY));
	Nan::Set(error_code, Nan::New("ERROR_COULD_NOT_ATTACH_TO_PROCESS").ToLocalChecked(), Nan::New<Number>(ERROR_COULD_NOT_ATTACH_TO_PROCESS));
	Nan::Set(error_code, Nan::New("ERROR_COULD_NOT_OPEN_FILE").ToLocalChecked(), Nan::New<Number>(ERROR_COULD_NOT_OPEN_FILE));
	Nan::Set(error_code, Nan::New("ERROR_COULD_NOT_MAP_FILE").ToLocalChecked(), Nan::New<Number>(ERROR_COULD_NOT_MAP_FILE));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_FILE").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_FILE));
	Nan::Set(error_code, Nan::New("ERROR_CORRUPT_FILE").ToLocalChecked(), Nan::New<Number>(ERROR_CORRUPT_FILE));
	Nan::Set(error_code, Nan::New("ERROR_UNSUPPORTED_FILE_VERSION").ToLocalChecked(), Nan::New<Number>(ERROR_UNSUPPORTED_FILE_VERSION));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_REGULAR_EXPRESSION").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_REGULAR_EXPRESSION));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_HEX_STRING").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_HEX_STRING));
	Nan::Set(error_code, Nan::New("ERROR_SYNTAX_ERROR").ToLocalChecked(), Nan::New<Number>(ERROR_SYNTAX_ERROR));
	Nan::Set(error_code, Nan::New("ERROR_LOOP_NESTING_LIMIT_EXCEEDED").ToLocalChecked(), Nan::New<Number>(ERROR_LOOP_NESTING_LIMIT_EXCEEDED));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_LOOP_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_LOOP_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_TAG_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_TAG_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_META_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_META_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_STRING_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_STRING_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_UNREFERENCED_STRING").ToLocalChecked(), Nan::New<Number>(ERROR_UNREFERENCED_STRING));
	Nan::Set(error_code, Nan::New("ERROR_UNDEFINED_STRING").ToLocalChecked(), Nan::New<Number>(ERROR_UNDEFINED_STRING));
	Nan::Set(error_code, Nan::New("ERROR_UNDEFINED_IDENTIFIER").ToLocalChecked(), Nan::New<Number>(ERROR_UNDEFINED_IDENTIFIER));
	Nan::Set(error_code, Nan::New("ERROR_MISPLACED_ANONYMOUS_STRING").ToLocalChecked(), Nan::New<Number>(ERROR_MISPLACED_ANONYMOUS_STRING));
	Nan::Set(error_code, Nan::New("ERROR_INCLUDES_CIRCULAR_REFERENCE").ToLocalChecked(), Nan::New<Number>(ERROR_INCLUDES_CIRCULAR_REFERENCE));
	Nan::Set(error_code, Nan::New("ERROR_INCLUDE_DEPTH_EXCEEDED").ToLocalChecked(), Nan::New<Number>(ERROR_INCLUDE_DEPTH_EXCEEDED));
	Nan::Set(error_code, Nan::New("ERROR_WRONG_TYPE").ToLocalChecked(), Nan::New<Number>(ERROR_WRONG_TYPE));
	Nan::Set(error_code, Nan::New("ERROR_EXEC_STACK_OVERFLOW").ToLocalChecked(), Nan::New<Number>(ERROR_EXEC_STACK_OVERFLOW));
	Nan::Set(error_code, Nan::New("ERROR_SCAN_TIMEOUT").ToLocalChecked(), Nan::New<Number>(ERROR_SCAN_TIMEOUT));
	Nan::Set(error_code, Nan::New("ERROR_TOO_MANY_SCAN_THREADS").ToLocalChecked(), Nan::New<Number>(ERROR_TOO_MANY_SCAN_THREADS));
	Nan::Set(error_code, Nan::New("ERROR_CALLBACK_ERROR").ToLocalChecked(), Nan::New<Number>(ERROR_CALLBACK_ERROR));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_ARGUMENT").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_ARGUMENT));
	Nan::Set(error_code, Nan::New("ERROR_TOO_MANY_MATCHES").ToLocalChecked(), Nan::New<Number>(ERROR_TOO_MANY_MATCHES));
	Nan::Set(error_code, Nan::New("ERROR_INTERNAL_FATAL_ERROR").ToLocalChecked(), Nan::New<Number>(ERROR_INTERNAL_FATAL_ERROR));
	Nan::Set(error_code, Nan::New("ERROR_NESTED_FOR_OF_LOOP").ToLocalChecked(), Nan::New<Number>(ERROR_NESTED_FOR_OF_LOOP));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_FIELD_NAME").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_FIELD_NAME));
	Nan::Set(error_code, Nan::New("ERROR_UNKNOWN_MODULE").ToLocalChecked(), Nan::New<Number>(ERROR_UNKNOWN_MODULE));
	Nan::Set(error_code, Nan::New("ERROR_NOT_A_STRUCTURE").ToLocalChecked(), Nan::New<Number>(ERROR_NOT_A_STRUCTURE));
	Nan::Set(error_code, Nan::New("ERROR_NOT_INDEXABLE").ToLocalChecked(), Nan::New<Number>(ERROR_NOT_INDEXABLE));
	Nan::Set(error_code, Nan::New("ERROR_NOT_A_FUNCTION").ToLocalChecked(), Nan::New<Number>(ERROR_NOT_A_FUNCTION));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_FORMAT").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_FORMAT));
	Nan::Set(error_code, Nan::New("ERROR_TOO_MANY_ARGUMENTS").ToLocalChecked(), Nan::New<Number>(ERROR_TOO_MANY_ARGUMENTS));
	Nan::Set(error_code, Nan::New("ERROR_WRONG_ARGUMENTS").ToLocalChecked(), Nan::New<Number>(ERROR_WRONG_ARGUMENTS));
	Nan::Set(error_code, Nan::New("ERROR_WRONG_RETURN_TYPE").ToLocalChecked(), Nan::New<Number>(ERROR_WRONG_RETURN_TYPE));
	Nan::Set(error_code, Nan::New("ERROR_DUPLICATED_STRUCTURE_MEMBER").ToLocalChecked(), Nan::New<Number>(ERROR_DUPLICATED_STRUCTURE_MEMBER));
	Nan::Set(error_code, Nan::New("ERROR_EMPTY_STRING").ToLocalChecked(), Nan::New<Number>(ERROR_EMPTY_STRING));
	Nan::Set(error_code, Nan::New("ERROR_DIVISION_BY_ZERO").ToLocalChecked(), Nan::New<Number>(ERROR_DIVISION_BY_ZERO));
	Nan::Set(error_code, Nan::New("ERROR_REGULAR_EXPRESSION_TOO_LARGE").ToLocalChecked(), Nan::New<Number>(ERROR_REGULAR_EXPRESSION_TOO_LARGE));
	Nan::Set(error_code, Nan::New("ERROR_TOO_MANY_RE_FIBERS").ToLocalChecked(), Nan::New<Number>(ERROR_TOO_MANY_RE_FIBERS));
	Nan::Set(error_code, Nan::New("ERROR_COULD_NOT_READ_PROCESS_MEMORY").ToLocalChecked(), Nan::New<Number>(ERROR_COULD_NOT_READ_PROCESS_MEMORY));
	Nan::Set(error_code, Nan::New("ERROR_INVALID_EXTERNAL_VARIABLE_TYPE").ToLocalChecked(), Nan::New<Number>(ERROR_INVALID_EXTERNAL_VARIABLE_TYPE));
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

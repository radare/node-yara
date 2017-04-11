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
	/**
	 ** Not really much we can do with a failure here.  Perhaps we would be
	 ** better off doing this on-demand by the first scanner object attempting
	 ** to use YARA.
	 **/
	yr_initialize();

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

	Nan::SetPrototypeMethod(tpl, "addRules", AddRules);

	ScannerWrap_constructor.Reset(tpl);
	exports->Set(Nan::New("ScannerWrap").ToLocalChecked(),
			Nan::GetFunction(tpl).ToLocalChecked());
}

ScannerWrap::ScannerWrap() : compiler(NULL), rules(NULL) {
	pthread_rwlock_init(&lock, NULL);
}

ScannerWrap::~ScannerWrap() {
	if (compiler) {
		yr_compiler_destroy(compiler);
		compiler = NULL;
	}

	if (rules) {
		yr_rules_destroy(rules);
		rules = NULL;
	}

	pthread_rwlock_destroy(&lock);
}

void ScannerWrap::lock_read(void) {
	pthread_rwlock_rdlock(&lock);
}

void ScannerWrap::lock_write(void) {
	pthread_rwlock_wrlock(&lock);
}

void ScannerWrap::unlock(void) {
	pthread_rwlock_unlock(&lock);
}

class AsyncAddRules : public Nan::AsyncWorker {
public:
	AsyncAddRules(
			ScannerWrap* scanner,
			std::string rules,
			Nan::Callback *callback
		) : Nan::AsyncWorker(callback), scanner_(scanner), rules_(rules) {}
	
	~AsyncAddRules() {}

	void Execute() {
		scanner_->lock_write();

		int rc;

		if (! scanner_->compiler) {
			rc = yr_compiler_create(&scanner_->compiler);
			if (rc != ERROR_SUCCESS) 
				SetErrorMessage("yr_compiler_create() failed: ERROR_INSUFICENT_MEMORY");
		}

		if (scanner_->compiler) {
			rc = yr_compiler_add_string(scanner_->compiler, rules_.c_str(), NULL);
			if (rc > 0) {
				SetErrorMessage("yr_compiler_add_string() failed: TODO more information");
			} else {
				if (scanner_->rules) {
					yr_rules_destroy(scanner_->rules);
					scanner_->rules = NULL;
				}
				rc = yr_compiler_get_rules(scanner_->compiler, &scanner_->rules);
				if (rc != ERROR_SUCCESS)
					SetErrorMessage("yr_compiler_get_rules() failed: ERROR_INSUFICENT_MEMORY");
			}
		}

		// TODO: Set a compiler callback and record errors
		// TODO: Throw an exception if any found
		
		scanner_->unlock();
	}

protected:

	void HandleOKCallback() {
		Local<Value> argv[1];

		argv[0] = Nan::Null();
		
		callback->Call(1, argv);
	}

private:
	ScannerWrap* scanner_;
	std::string rules_;
};

NAN_METHOD(ScannerWrap::AddRules) {
	Nan::HandleScope scope;
	
	if (info.Length() < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}

	if (! info[0]->IsString()) {
		Nan::ThrowError("Rules argument must be a string");
		return;
	}

	if (! info[1]->IsFunction()) {
		Nan::ThrowError("Callback argument must be a function");
		return;
	}

	Nan::Callback* callback = new Nan::Callback(info[1].As<Function>());
	
	ScannerWrap* scanner = ScannerWrap::Unwrap<ScannerWrap>(info.This());

	AsyncAddRules* async_add_rules = new AsyncAddRules(
			scanner,
			std::string(*Nan::Utf8String(info[0])),
			callback
		);

	Nan::AsyncQueueWorker(async_add_rules);

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

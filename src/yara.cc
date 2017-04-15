#ifndef YARA_CC
#define YARA_CC

#include <map>

#include <stdio.h>
#include <string.h>
#include "yara.h"

const char* yara_strerror(int code) {
	return strerror(code);
}

namespace yara {

static Nan::Persistent<FunctionTemplate> ScannerWrap_constructor;

std::map<int, const char*> error_codes;

#define MAP_ERROR_CODE(name, code) error_codes[code] = name

#define ERROR_UNKNOWN_STRING "ERROR_UNKNOWN"

const char* getErrorString(int code) {
	size_t count = error_codes.count(code);
	if (count > 0)
		return error_codes[code];
	else
		return ERROR_UNKNOWN_STRING;
}

void InitAll(Handle<Object> exports) {
   MAP_ERROR_CODE("ERROR_SUCCESS", ERROR_SUCCESS);
   MAP_ERROR_CODE("ERROR_INSUFICIENT_MEMORY", ERROR_INSUFICIENT_MEMORY);
   MAP_ERROR_CODE("ERROR_COULD_NOT_ATTACH_TO_PROCESS", ERROR_COULD_NOT_ATTACH_TO_PROCESS);
   MAP_ERROR_CODE("ERROR_COULD_NOT_OPEN_FILE", ERROR_COULD_NOT_OPEN_FILE);
   MAP_ERROR_CODE("ERROR_COULD_NOT_MAP_FILE", ERROR_COULD_NOT_MAP_FILE);
   MAP_ERROR_CODE("ERROR_INVALID_FILE", ERROR_INVALID_FILE);
   MAP_ERROR_CODE("ERROR_CORRUPT_FILE", ERROR_CORRUPT_FILE);
   MAP_ERROR_CODE("ERROR_UNSUPPORTED_FILE_VERSION", ERROR_UNSUPPORTED_FILE_VERSION);
   MAP_ERROR_CODE("ERROR_INVALID_REGULAR_EXPRESSION", ERROR_INVALID_REGULAR_EXPRESSION);
   MAP_ERROR_CODE("ERROR_INVALID_HEX_STRING", ERROR_INVALID_HEX_STRING);
   MAP_ERROR_CODE("ERROR_SYNTAX_ERROR", ERROR_SYNTAX_ERROR);
   MAP_ERROR_CODE("ERROR_LOOP_NESTING_LIMIT_EXCEEDED", ERROR_LOOP_NESTING_LIMIT_EXCEEDED);
   MAP_ERROR_CODE("ERROR_DUPLICATED_LOOP_IDENTIFIER", ERROR_DUPLICATED_LOOP_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_DUPLICATED_IDENTIFIER", ERROR_DUPLICATED_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_DUPLICATED_TAG_IDENTIFIER", ERROR_DUPLICATED_TAG_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_DUPLICATED_META_IDENTIFIER", ERROR_DUPLICATED_META_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_DUPLICATED_STRING_IDENTIFIER", ERROR_DUPLICATED_STRING_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_UNREFERENCED_STRING", ERROR_UNREFERENCED_STRING);
   MAP_ERROR_CODE("ERROR_UNDEFINED_STRING", ERROR_UNDEFINED_STRING);
   MAP_ERROR_CODE("ERROR_UNDEFINED_IDENTIFIER", ERROR_UNDEFINED_IDENTIFIER);
   MAP_ERROR_CODE("ERROR_MISPLACED_ANONYMOUS_STRING", ERROR_MISPLACED_ANONYMOUS_STRING);
   MAP_ERROR_CODE("ERROR_INCLUDES_CIRCULAR_REFERENCE", ERROR_INCLUDES_CIRCULAR_REFERENCE);
   MAP_ERROR_CODE("ERROR_INCLUDE_DEPTH_EXCEEDED", ERROR_INCLUDE_DEPTH_EXCEEDED);
   MAP_ERROR_CODE("ERROR_WRONG_TYPE", ERROR_WRONG_TYPE);
   MAP_ERROR_CODE("ERROR_EXEC_STACK_OVERFLOW", ERROR_EXEC_STACK_OVERFLOW);
   MAP_ERROR_CODE("ERROR_SCAN_TIMEOUT", ERROR_SCAN_TIMEOUT);
   MAP_ERROR_CODE("ERROR_TOO_MANY_SCAN_THREADS", ERROR_TOO_MANY_SCAN_THREADS);
   MAP_ERROR_CODE("ERROR_CALLBACK_ERROR", ERROR_CALLBACK_ERROR);
   MAP_ERROR_CODE("ERROR_INVALID_ARGUMENT", ERROR_INVALID_ARGUMENT);
   MAP_ERROR_CODE("ERROR_TOO_MANY_MATCHES", ERROR_TOO_MANY_MATCHES);
   MAP_ERROR_CODE("ERROR_INTERNAL_FATAL_ERROR", ERROR_INTERNAL_FATAL_ERROR);
   MAP_ERROR_CODE("ERROR_NESTED_FOR_OF_LOOP", ERROR_NESTED_FOR_OF_LOOP);
   MAP_ERROR_CODE("ERROR_INVALID_FIELD_NAME", ERROR_INVALID_FIELD_NAME);
   MAP_ERROR_CODE("ERROR_UNKNOWN_MODULE", ERROR_UNKNOWN_MODULE);
   MAP_ERROR_CODE("ERROR_NOT_A_STRUCTURE", ERROR_NOT_A_STRUCTURE);
   MAP_ERROR_CODE("ERROR_NOT_INDEXABLE", ERROR_NOT_INDEXABLE);
   MAP_ERROR_CODE("ERROR_NOT_A_FUNCTION", ERROR_NOT_A_FUNCTION);
   MAP_ERROR_CODE("ERROR_INVALID_FORMAT", ERROR_INVALID_FORMAT);
   MAP_ERROR_CODE("ERROR_TOO_MANY_ARGUMENTS", ERROR_TOO_MANY_ARGUMENTS);
   MAP_ERROR_CODE("ERROR_WRONG_ARGUMENTS", ERROR_WRONG_ARGUMENTS);
   MAP_ERROR_CODE("ERROR_WRONG_RETURN_TYPE", ERROR_WRONG_RETURN_TYPE);
   MAP_ERROR_CODE("ERROR_DUPLICATED_STRUCTURE_MEMBER", ERROR_DUPLICATED_STRUCTURE_MEMBER);
   MAP_ERROR_CODE("ERROR_EMPTY_STRING", ERROR_EMPTY_STRING);
   MAP_ERROR_CODE("ERROR_DIVISION_BY_ZERO", ERROR_DIVISION_BY_ZERO);
   MAP_ERROR_CODE("ERROR_REGULAR_EXPRESSION_TOO_LARGE", ERROR_REGULAR_EXPRESSION_TOO_LARGE);
   MAP_ERROR_CODE("ERROR_TOO_MANY_RE_FIBERS", ERROR_TOO_MANY_RE_FIBERS);
   MAP_ERROR_CODE("ERROR_COULD_NOT_READ_PROCESS_MEMORY", ERROR_COULD_NOT_READ_PROCESS_MEMORY);
   MAP_ERROR_CODE("ERROR_INVALID_EXTERNAL_VARIABLE_TYPE", ERROR_INVALID_EXTERNAL_VARIABLE_TYPE);

	ExportFunctions (exports);

	ScannerWrap::Init(exports);
}

NODE_MODULE(yara, InitAll)

void ExportFunctions(Handle<Object> target) {
	Nan::Set(target, Nan::New("initialize").ToLocalChecked(),
			Nan::New<FunctionTemplate>(Initialize)->GetFunction());
}

class AsyncInitialize : public Nan::AsyncWorker {
public:
	AsyncInitialize(
			Nan::Callback *callback
		) : Nan::AsyncWorker(callback) {}
	
	~AsyncInitialize() {}

	void Execute() {
		int rc = yr_initialize();
		if (rc != ERROR_SUCCESS) {
			std::string errorstr = std::string("yr_initialize() failed: ") + getErrorString(rc);
			SetErrorMessage(errorstr.c_str());
		}
	}

protected:
	void HandleOKCallback() {
		Local<Value> argv[1];

		argv[0] = Nan::Null();
		
		callback->Call(1, argv);
	}
};

NAN_METHOD(Initialize) {
	Nan::HandleScope scope;

	if (info.Length() < 1) {
		Nan::ThrowError("One argument is required");
		return;
	}

	if (! info[0]->IsFunction()) {
		Nan::ThrowError("Callback argument must be a function");
		return;
	}

	Nan::Callback* callback = new Nan::Callback(info[0].As<Function>());

	AsyncInitialize* async_initialize = new AsyncInitialize(callback);

	Nan::AsyncQueueWorker(async_initialize);

	info.GetReturnValue().Set(info.This());
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

NAN_METHOD(ScannerWrap::New) {
	Nan::HandleScope scope;
	
	ScannerWrap* scanner = new ScannerWrap();

	scanner->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
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

NAN_METHOD(ScannerWrap::ErrorCodeToString) {
	Nan::HandleScope scope;

	if (info.Length() < 1) {
		Nan::ThrowError("One argument is required");
		return;
	}

	if (! info[0]->IsInt32()) {
		Nan::ThrowError("Code argument must be a int32");
		return;
	}

	int code = Nan::To<v8::Int32>(info[0]).ToLocalChecked()->Value();

	info.GetReturnValue().Set(Nan::New<String>(getErrorString(code)).ToLocalChecked());
}

}; /* namespace yara */

#endif /* YARA_CC */

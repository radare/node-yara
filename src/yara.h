#ifndef YARA_H
#define YARA_H

#include <pthread.h>

#include <nan.h>

#include <yara.h>

using namespace v8;

namespace yara {

void ExportConstants(Handle<Object> target);

class ScannerWrap : public Nan::ObjectWrap {
public:
	static void Init(Handle<Object> exports);

	void lock_read(void);
	void lock_write(void);
	void unlock(void);

	YR_COMPILER* compiler;
	YR_RULES* rules;

private:
	ScannerWrap();
	~ScannerWrap();

	static NAN_METHOD(New);
	static NAN_METHOD(AddRules);

	pthread_rwlock_t lock;
};

}; /* namespace yara */

#endif /* YARA_H */

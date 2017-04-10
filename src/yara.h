#ifndef YARA_H
#define YARA_H

#include <nan.h>

using namespace v8;

namespace yara {

void ExportConstants(Handle<Object> target);

class ScannerWrap : public Nan::ObjectWrap {
public:
	static void Init(Handle<Object> exports);

private:
	ScannerWrap();
	~ScannerWrap();

	static NAN_METHOD(Destroy);
	static NAN_METHOD(New);
};

}; /* namespace yara */

#endif /* YARA_H */

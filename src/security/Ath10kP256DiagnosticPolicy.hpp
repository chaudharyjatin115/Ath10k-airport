#pragma once
#include <stdint.h>
#include <string.h>
namespace AthSecurity {
inline bool p256DiagnosticDevice(uint16_t vendor,uint16_t device,uint16_t subvendor,uint16_t subsystem){
 return vendor==0x168c && ((device==0x42 && subvendor==0x1a3b && subsystem==0x2b51) ||
                           (device==0x3e && subvendor==0x1028 && subsystem==0x0310));
}
// Deliberately one known OS build for the first private-ABI diagnostic. This
// is a test admission guard, not proof that CoreCrypto's runtime ABI is valid.
inline bool p256DiagnosticKernel(int major,int minor,int revision,const char *build,const char *kernel){
 if(major!=24 || minor!=6 || revision!=0 || !build || !kernel)return false;
 const bool validBuild = (strcmp(build,"24G90")==0 || strcmp(build,"24H241")==0 ||
                          (build[0]=='2' && build[1]=='4' && strcmp(build,"24G91")!=0));
 if(!validBuild)return false;
 static constexpr char suffix[]="/RELEASE_X86_64";
 static constexpr char tagPrefix[]="root:xnu-11417.140.69";
 size_t length=strlen(kernel);if(length && kernel[length-1]=='\n')--length;
 if(length<sizeof(suffix)-1 || memcmp(kernel+length-(sizeof(suffix)-1),suffix,sizeof(suffix)-1)!=0)return false;
 const size_t prefixLen=sizeof(tagPrefix)-1;
 if(length<prefixLen)return false;
 for(size_t i=0;i<=length-prefixLen;++i){
     if(memcmp(kernel+i,tagPrefix,prefixLen)==0)return true;
 }
 return false;
}
// Publication and cancellation linearize without taking any driver/registry
// lock. A writer that wins may finish; a winning cancellation forbids writes.
class P256DiagnosticPublication {
 enum : uint32_t {Pending,Writing,Reported,Cancelled};
 alignas(4) uint32_t state=Pending;
 bool change(uint32_t from,uint32_t to){return __atomic_compare_exchange_n(&state,&from,to,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);}
public:
 P256DiagnosticPublication()=default;
 P256DiagnosticPublication(const P256DiagnosticPublication &)=delete;
 P256DiagnosticPublication &operator=(const P256DiagnosticPublication &)=delete;
 static_assert(__atomic_always_lock_free(sizeof(uint32_t),nullptr),"Diagnostic publication must not add a runtime atomic lock");
 bool pending() const {return __atomic_load_n(&state,__ATOMIC_ACQUIRE)==Pending;}
 bool cancelled() const {return __atomic_load_n(&state,__ATOMIC_ACQUIRE)==Cancelled;}
 bool beginReport(){return change(Pending,Writing);}
 bool finishReport(){return change(Writing,Reported);}
 bool cancel(){return change(Pending,Cancelled);}
};
}

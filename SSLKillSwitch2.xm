#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <dlfcn.h>
#import <substrate.h>

extern const char* __progname;

#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist"
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

static inline void SSKLog(NSString *format, ...)
{
	@autoreleasepool {
		NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 2: %@", format];
		va_list args;
		va_start(args, format);
		NSLogv(newFormat, args);
		va_end(args);
	}
}

static inline BOOL shouldHookFromPreference(NSString *preferenceSetting)
{
	@autoreleasepool {
		//Disable in apsd, prevent this break push notification
		if(strcmp(__progname, "apsd")==0) {
			return NO;
		}
		BOOL shouldHook = NO;
		NSDictionary* plist = [[NSDictionary alloc] initWithContentsOfFile:PREFERENCE_FILE]?:@{};
		shouldHook = [plist[preferenceSetting]?:@YES boolValue];
		SSKLog(@"Preference set to %d.", shouldHook);
		if(shouldHook) {
			NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
			bundleId = [bundleId stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
			NSString *excludedBundleIdsString = plist[@"excludedBundleIds"]?:@"";
			excludedBundleIdsString = [excludedBundleIdsString stringByReplacingOccurrencesOfString:@" " withString:@""];
			NSArray *excludedBundleIds = [excludedBundleIdsString componentsSeparatedByString:@","]?:@[];
			if ([excludedBundleIds containsObject:bundleId]) {
				SSKLog(@"Not hooking excluded bundle: %@", bundleId);
				shouldHook = NO;
			}
		}
		return shouldHook;
	}
}


#pragma mark SecureTransport hooks - iOS 9 and below
static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus replaced_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value)
{	
	if(option == kSSLSessionOptionBreakOnServerAuth) {
		return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
}

static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType);
static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType)
{
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);
	
	//SSLSetClientSideAuthenticate(sslContext, kNeverAuthenticate);
	//original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnCertRequested, false);
	original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
	//original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnClientAuth, false);
		
    return sslContext;
}

static OSStatus (*original_SSLHandshake)(SSLContextRef context);
static OSStatus replaced_SSLHandshake(SSLContextRef context)
{
	OSStatus result = original_SSLHandshake(context);
	if (result == errSSLServerAuthCompleted) {
		return original_SSLHandshake(context);
	}
	return result;
}

#pragma mark BoringSSL hooks - iOS 12 - 13

static int custom_verify_callback_that_does_not_validate(void *ssl, uint8_t *out_alert)
{
    return 0;
}

static void (*original_SSL_set_custom_verify)(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_set_custom_verify(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    original_SSL_set_custom_verify(ssl, 0, custom_verify_callback_that_does_not_validate);
}

static void (*original_SSL_CTX_set_custom_verify)(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_CTX_set_custom_verify(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert))
{
    original_SSL_CTX_set_custom_verify(ctx, 0, custom_verify_callback_that_does_not_validate);
}

static char *(*original_SSL_get_psk_identity)(void *ssl);
static char *replaced_SSL_get_psk_identity(void *ssl)
{
    return (char *)"notarealPSKidentity";
}


static BOOL (*original_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef  _Nullable *error);
static BOOL replaced_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef  _Nullable *error)
{
	BOOL ret = original_SecTrustEvaluateWithError(trust, NULL);
	if(error) {
		*error = NULL;
	}
	
	ret = YES;
	
	return ret;
}



static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, int *result);
static OSStatus ret_replaced_SecTrustEvaluate(SecTrustRef trust, int *result, OSStatus (*trustO)(SecTrustRef trust, int *result))
{
	OSStatus ret = trustO(trust, result);
	//if(result != NULL) {
	//	*result = 1;
	//}
	//ret = errSecSuccess;
	return ret;
}
static OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, int *result)
{
	return ret_replaced_SecTrustEvaluate(trust, result, original_SecTrustEvaluate);
}

static int (*original_boringssl_context_set_verify_mode)(void *ctx, int mode);
static int replaced_boringssl_context_set_verify_mode(void *ctx, int mode)
{
	return 0;
}



%ctor
{
	if(shouldHookFromPreference(PREFERENCE_KEY)) {
		// load for bind symbols
		dlopen("/usr/lib/libboringssl.dylib", RTLD_NOW);
		
		#define HOOKFN(fName) \
		void* sym##fName = dlsym(RTLD_DEFAULT, ""#fName""); \
		if(sym##fName != NULL) { \
			MSHookFunction(sym##fName,(void *)  replaced_##fName, (void **) &original_##fName); \
		} else { \
			SSKLog(@"Symbol[%s] Not Resolved.", ""#fName""); \
		}
		
		// Security.framework
		HOOKFN(SSLSetSessionOption)
		HOOKFN(SSLHandshake)
		HOOKFN(SSLCreateContext)
		
			HOOKFN(SecTrustEvaluateWithError)
		if(NO) {
			HOOKFN(SecTrustEvaluate)
		}
		
		// libboringssl.dylib
		HOOKFN(SSL_set_custom_verify)
		HOOKFN(SSL_CTX_set_custom_verify)
		HOOKFN(SSL_get_psk_identity)
		
		//if(NO) {
			HOOKFN(boringssl_context_set_verify_mode)
		//}
	}
}




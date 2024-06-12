#ifndef SEARCH_H
#define SEARCH_H

#include <CoreFoundation/CoreFoundation.h>

extern OSStatus KeyringSearch(CFStringRef by, CFStringRef query, CF_RETURNS_RETAINED CFDataRef *credential);

#endif 
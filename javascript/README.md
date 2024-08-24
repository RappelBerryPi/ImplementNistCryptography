# Using Javascript

Javascript obviously comes in two forms, one that runs in node.js and one that runs in browser.

## cryptography IN javascript

### node.js

node.JS uses node:crypto. what this is about will focus on WebCrypto as the API for browsers to implement cryptograpy.

### Javascript in Browser

Different browsers obviously implement cryptography using some underlying library, and in general those libraries may or may not
be NIST certified or use good cryptographic practices. So although the use of JavaScript in browser is the same in general across
all browser interfaces using WebCrypto so long as they comply with the [standard](https://www.w3.org/TR/WebCryptoAPI/), the underlying library is what needs to be certified
for NSIT CAVP and NIST CMVP to ensure that they're complying with requirements for good cryptographic practice.

## Looking into Javascript in Browser implementations

The general overview of Webcrypto is that it belongs to the Window that you are currently in. 

It's accessed via window.crypto. 

The underlying primitives come through the subtleCrypto interface (window.crypto.subtle)

You can get more information from [MDN](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt) and
various other pages on the MDN site.

For those security contexts or in organizations that are heavily regulated, it's probably not a good idea to use the
cryptography in browser to secure data, but it could potentially be used as an additional layer on top of already good
cryptography that has been FIPS validated such as the TLS that all modern browsers implement.

### Firefox

Firefox and Firefox based browsers internally use
[WebCryptoTask](https://searchfox.org/mozilla-central/source/dom/crypto/WebCryptoTask.cpp) which offload to PKCS#11
which means that they're using NSS (Network System Services)

### Chrome and Chromium based browsers

Chrome and other Chromium based browsers will use [blink/webcrypto](https://www.chromium.org/blink/webcrypto/) in their
C++ files [example](https://chromium.googlesource.com/chromium/src/+/HEAD/components/webcrypto/webcrypto_impl.cc) which
leads back to boringSSL (which is generally just OpenSSL by a different name with other more different API and ABI) see
[here](https://chromium.googlesource.com/chromium/src/+/HEAD/components/webcrypto/algorithms/aes_cbc.cc) for more
information around this.

### safari

Safari is built upon webkit. [Webkit crypto](https://github.com/WebKit/WebKit/tree/main/Source/WebCore/crypto) looks as
though it can use openssl, libgcrypt, or commoncrypto depending on how it's compiled. This is great not only for safari,
but all across the apple ecosystem, the use of cryptography will use common crypto more likely than not. This includes
all applications that are built on webkit, which is the only way that Apple allows applications to access the web. 

### other browsers

if browsers aren't built on one of these common platforms, its use of cryptography is likely not FIPS certified in any
capacity. Although this may not necessarily be the case. 

## Examples
THere are examples pulled from MDN on the use of cryptography in this directory as well. 
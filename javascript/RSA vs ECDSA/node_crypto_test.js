let crypto;
try {
    crypto = require('node:crypto');
} catch (err) {
    console.log("crypto not supported");
}

function generateRSAKeyPair(size) {
    let x = crypto.generateKeyPairSync("rsa", {
        modulusLength: size,
    });
    return [x.publicKey, x.privateKey];
}

function sign(privateKey) {
    return crypto.sign("SHA256", "abc", privateKey);
}
function verify(publicKey, signature) {
    return crypto.verify("SHA256", "abc", publicKey, signature);
}

function generateECKeyPair(curve) {
    //should be secp256r1 but for some reason that isn't supported?????
    let properCurves = ["secp256k1", "secp384r1", "secp521r1"];
    if (!(properCurves.includes(curve))) {
        throw "Invalid Curve. Must be one of: " + properCurves;
    }
    let x = crypto.generateKeyPairSync("ec", {
        namedCurve: curve,
    });
    return [x.publicKey, x.privateKey];
}

function test() {
    let ECDSASizes = ["secp256k1", "secp384r1", "secp521r1"];
    let RSASizes = [2048, 3072, 4096];
    let loopCount = 10000;
    let average = 5;
    for (let size of ECDSASizes) {
        let sign_times = [];
        let verify_times = [];
        for (let i = 0; i < average; i++) {
            let x = generateECKeyPair(size);
            let publicKey = x[0];
            let privateKey = x[1];
            let signatures = [];

            let start = Date.now();
            for (let i = 0; i < loopCount; i++) {
                let signature = sign(privateKey);
                signatures.push(signature);
            }
            let end = Date.now();
            let timeElapsed = end - start;
            let sign_time = (timeElapsed / 1000);
            sign_times.push(sign_time);
            let signs_per_second = loopCount / sign_time;
            console.log(`ECDSA (${size}) signs/second: ${signs_per_second}`);

            start = Date.now();
            for (let i = 0; i < loopCount; i++) {
                verify(publicKey, signatures[i]);
            }
            end = Date.now();
            timeElapsed = end - start;
            let verify_time = (timeElapsed / 1000);
            verify_times.push(verify_time);
            let verifies_per_second = loopCount / verify_time;
            console.log(`ECDSA (${size}) verifications/second: ${verifies_per_second}`);
            console.log("");
        }
        console.log(`${average} run average:`)
        let sign_time_average = sign_times.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / average;
        let verify_time_average = verify_times.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / average;
        let average_signs = loopCount / (sign_time_average)
        let average_verifies = loopCount / (verify_time_average)
        console.log(`\tECDSA (${size}) average signs/second: ${average_signs}`)
        console.log(`\tECDSA (${size}) average verifications/second: ${average_verifies}`)
    }
    //RSA
    for (let size of RSASizes) {
        let sign_times = [];
        let verify_times = [];
        for (let i = 0; i < average; i++) {
            let x = generateRSAKeyPair(size);
            let publicKey = x[0];
            let privateKey = x[1];
            let signatures = [];

            let start = Date.now();
            for (let i = 0; i < loopCount; i++) {
                let signature = sign(privateKey);
                signatures.push(signature);
            }
            let end = Date.now();
            let timeElapsed = end - start;
            let sign_time = (timeElapsed / 1000);
            sign_times.push(sign_time);
            let signs_per_second = loopCount / sign_time;
            console.log(`RSA (${size}) signs/second: ${signs_per_second}`);

            start = Date.now();
            for (let i = 0; i < loopCount; i++) {
                verify(publicKey, signatures[i]);
            }
            end = Date.now();
            timeElapsed = end - start;
            let verify_time = (timeElapsed / 1000);
            verify_times.push(verify_time);
            let verifies_per_second = loopCount / verify_time;
            console.log(`RSA (${size}) verifications/second: ${verifies_per_second}`);
            console.log("");
        }
        console.log(`${average} run average:`)
        let sign_time_average = sign_times.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / average;
        let verify_time_average = verify_times.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / average;
        let average_signs = loopCount / (sign_time_average)
        let average_verifies = loopCount / (verify_time_average)
        console.log(`\tRSA (${size}) average signs/second: ${average_signs}`)
        console.log(`\tRSA (${size}) average verifications/second: ${average_verifies}`)
    }
}
/*
let x = generateRSAKeyPair(2048);
console.log(signRSA(x[1]));
*/

test();
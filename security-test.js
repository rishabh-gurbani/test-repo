const fs = require("fs");
const { execSync } = require("child_process");

console.log("🔍 Running security tests...");

// Test 1: Try to read app code
try {
    fs.readFileSync("/home/app/script.js");
    console.log("❌ SECURITY RISK: Can read app code!");
} catch (e) {
    console.log("✅ Cannot read app code");
}

// Test 2: Try to read sensitive system files
try {
    fs.readFileSync("/etc/shadow");
    console.log("❌ SECURITY RISK: Can read system files!");
} catch (e) {
    console.log("✅ Cannot read system files");
}

// Test 3: Try to write outside build directory
try {
    fs.writeFileSync("/home/builder/malicious-file", "hack");
    console.log("❌ SECURITY RISK: Can write outside build directory!");
} catch (e) {
    console.log("✅ Cannot write outside build directory");
}

// Test 4: Try to execute privileged commands
try {
    execSync("sudo ls");
    console.log("❌ SECURITY RISK: Can execute sudo!");
} catch (e) {
    console.log("✅ Cannot execute sudo");
}

// Test 5: Print current user and permissions
console.log("\n🔍 Environment Info:");
console.log("AWS Secret:", process.env.AWS_ACCESS_KEY_ID);
console.log("Current user:", execSync("whoami").toString());
console.log("User groups:", execSync("groups").toString());
console.log("Current directory:", execSync("pwd").toString());
console.log("Parent directory listing:", execSync("ls -la ..").toString());

// Create dist folder with dummy content for the build process
fs.mkdirSync("dist", { recursive: true });
fs.writeFileSync("dist/index.html", "test");

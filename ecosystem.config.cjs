module.exports = {
  apps: [{
    name: "lan-inventory",
    script: "server.js",
    cwd: __dirname,
    env: {
      NODE_ENV: "production",
      PORT: 3000,
      BIND_ADDRESS: "127.0.0.1"
    }
  }]
};

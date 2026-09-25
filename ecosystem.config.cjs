module.exports = {
  apps: [{
    name: "lan-inventory",
    script: "server.js",
    cwd: __dirname,
    node_args: "--env-file=.env",
    env: {
      NODE_ENV: "production"
    }
  }]
};

module.exports = {
  apps: [
    {
      name: 'vpn-manager',
      script: '/home/user/vpn-manager/.venv/bin/python',
      args: '-m vpn_manager',
      cwd: '/home/user/vpn-manager',
      env: {
        VPNM_SANDBOX: 'false',
        VPNM_ADMIN_USER: 'admin',
        VPNM_ADMIN_PASSWORD_HASH: 'pbkdf2_sha256$600000$749e099ea0979d9f07fd65de4bd6f238$d78900e4478c3c3f270f43e92115ae31ea76c4c07042e9e204a98e31c94ef42c',
        VPNM_SECRET_KEY: 'd195cd2c99efc96c575c91d6906f64c12daf09f49c7e2f3df149cc1bd4bae829',
        VPNM_COOKIE_SECURE: 'false'
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork'
    }
  ]
}

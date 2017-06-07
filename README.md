# KDCAuthenticator

KDC authenticator allows to authenticate the JuypterHub user using Kerberos protocol.

# Install, Configure and Run

1. Install KDC Authenticator -

    Run the following command at kdcauthenticator directory

    ```
    pip3 install jupyterhub-kdcauthenticator
    ```

    Or clone the repository and install -
    ```
    git clone https://github.com/bloomberg/kdcauthenticator.git
    cd kdcauthenticator
    pip3 install -e .
    ```

2. Configure JupyterHub for KDC Authenticator

    Add the following line to the jupyterHub config file
    ```
    c.JupyterHub.authenticator_class = 'kdcauthenticator.kdcauthenticator.KDCAuthenticator'
    ```
    Optionally you can add the following lines to create local system users
    ```
    c.LocalAuthenticator.add_user_cmd = ['adduser', '-m']
    c.LocalAuthenticator.create_system_users = True
    ```

3. The Service principal for JupyterHub authenticator is configured to "HTTP" but can be configured by -

    ```
    c.KDCAuthenticator.service_name = '<HTTP-Service-Principal>'
    ```

4. Run the JupyterHub command with Kerberos environment variables -

    ```
    KRB5_CONFIG=[Kerberos-config-path] KRB5_KTNAME=[HTTP-Service-Principle-Keytab-path] jupyterhub --ip=0.0.0.0 --port=8000 --no-ssl --config=[jupyterHub-config-file-path]
    ```






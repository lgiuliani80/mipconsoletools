# Usage

## Configuration

* appsettings.json :

    ```json
    {
      "MIP": {
        "LogLevel": "Trace",
        "ClientId": "YOUR_APP_CLIENT_ID_HERE",
        "TenantId": "YOUR_TENANT_ID_HERE",
        "ClientSecret": "YOUR_CLIENT_SECRET_HERE",
        "AppName": "ICRS (AL03703_I_O)",
        "AppVersion": "1.0",
        "Username": "USERNAME_EMAIL_HERE",
        "DelegatedUser": "DELEGATED_USER_EMAIL_HERE_OR_EMPTY",
        "IsInteractive": true | false
      }
    }
    ```

    `Username` must be a valid E-Mail within the tenant.
    `DelegatedUser` is optional. It is needed for delabeling of files.  
    If `IsInteractive` is true, then the app will use the interactive flow to authenticate the user. Otherwise, it will use the client credentials flow.  
    If you want to use the interactive flow, set `ClientId` to `c00e9d32-3c8d-4a7d-832b-029040e7db99`; in this case `ClientSecret` will be ignored.

## Run

```sh
./mipconsoletools --action=<action> --input=<input> --output=<output> --msgTemplate=<msgTemplate> --label=<label>
```

Arguments:

* `action` [mandatory] =
  - `decrypt` : decrypts file in "input" creating the output file in "output". 
    In case of .eml input file "msgTemplate" is mandatory and must point to a valid .msg file.
  - listlabels : lists all sensitivity labels in the tenant.
  - `label` : labels "input" file with the label specified in "label".
  - `delabel` : removes sensitivity label on "input" file creating the output file in "output".
  - `inspect` : decrypts a .msg file and prints the content (body) to the console.
* `input` [mandatory] = path to the input file.
* `output` [mandatory, except for `inspect`] = path to the output file.
* `label` [mandatory, only for `label`] = name or GUID or description of the label to apply to the file.
* `msgTemplate` [mandatory, only for `decrypt` and `inspect` of .eml files] = path to the .msg file to use as template for the decrypted .msg file.

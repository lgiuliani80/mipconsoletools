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
        "DelegatedUser": "DELEGATED_USER_EMAIL_HERE_OR_EMPTY"
      }
    }
    ```

    "DelegatedUser" is optional. It is needed for delabeling of files.

## Run

```sh
./mipconsoletools --action=<action> --input=<input> --output=<output> --msgTemplate=<msgTemplate>
```

Arguments:

* `action` [mandatory] =
  - `decrypt` : decrypts file in "input" creating the output file in "output". 
    In case of .eml input file "msgTemplate" is mandatory and must point to a valid .msg file.
  - `delabel` : removes sensitivity label on "input" file creating the output file in "output".
  - `inpect` : decrypts a .msg file and prints the content (body) to the console.
* `input` [mandatory] = path to the input file.
* `output` [mandatory, except for `inspect`] = path to the output file.
* `msgTemplate` [mandatory, only for `decrypt` of .eml files] = path to the .msg file to use as template for the decrypted .msg file.

> _NOTE_: as far as LLoyds use cases are concerned, there is not any Windows-specific code, so the `<TargetFramework>` in the `.csproj` can be safely turned to `net6.0` 
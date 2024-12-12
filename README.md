# Hyster/Yale PC Service Tool

This is a password generator for the Hyster/Yale PC Service Tool.

[Try It](https://brcolow.github.io/pc-service-tool-pw-gen/)

Please be aware that the default brand is Hyster. If you want to use a different
brand you have to edit `NMHG PC Service Tool.exe.config` (in the same directory
as the main `NMHG PC Service Tool.exe` binary) accordingly:

That is to change from the default `Hyster` to `Yale` you have to edit the following line:

```xml
<add key="AppBrand" value="Hyster"/>
```

to:

```xml
<add key="AppBrand" value="Yale"/>
```
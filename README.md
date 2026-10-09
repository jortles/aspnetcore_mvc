# ASP.NET Core (.NET 10) MVC Boilerplate

## Running

Requirements: the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and a SQL Server instance.

Configuration is read from user secrets (run these from the `aspnetcore_mvc` project folder):

```bash
cd aspnetcore_mvc

# Database connection string. For a local SQL Server with a self-signed certificate, keep TrustServerCertificate=True
# (add it to an AppData secret you already have from the ASP.NET Core 3.1 version).
dotnet user-secrets set "ConnectionStrings:AppData" "Server=localhost;Database=aspnetcore_mvc;User Id=<user>;Password=<password>;TrustServerCertificate=True"

# SMTP settings used for the confirmation, two-factor and password reset emails (the app does not start without this section).
dotnet user-secrets set "EmailConfiguration:From" "<sender address>"
dotnet user-secrets set "EmailConfiguration:SmtpServer" "<smtp host>"
dotnet user-secrets set "EmailConfiguration:Port" "465"
dotnet user-secrets set "EmailConfiguration:Email" "<smtp user>"
dotnet user-secrets set "EmailConfiguration:Password" "<smtp password>"
```

Create the database and start the app:

```bash
dotnet tool install --global dotnet-ef --version "10.*"   # once
dotnet ef database update
dotnet run
```

The app listens on https://localhost:5001 and http://localhost:5000 (see `Properties/launchSettings.json`).

### AutoMapper license key

AutoMapper 15 and later are licensed by Lucky Penny Software (a free Community license is available). Without a key the app runs, and AutoMapper logs that this is allowed for development and testing only; production use requires a license. Store the key in user secrets, never in the repository:

```bash
dotnet user-secrets set "AutoMapper:LicenseKey" "<your license key>"
```

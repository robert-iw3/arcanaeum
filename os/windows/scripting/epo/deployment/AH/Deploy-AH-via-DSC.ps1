# Deploy-AH-via-DSC.ps1
Configuration AHDeploymentConfig {
    param([string[]]$NodeName)

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName NetworkingDsc

    Node $NodeName {
        # 1. Install AH
        Package 'InstallAH' {
            Ensure      = 'Present'
            Name        = 'Trellix Agent Handler'
            Path        = 'C:\Temp\ePO_5.10.0\setup.exe'
            ProductId   = 'Your-Product-GUID-Here'   # from MSI
            Arguments   = 'INSTALLAH=1 ENABLEFIPSMODE=1 /quiet'
        }

        # 2. Firewall (idempotent)
        Firewall 'ePOAHPorts' {
            Name      = 'ePO-AH-Ports'
            DisplayName = 'Trellix AH (80,443,8443)'
            Ensure    = 'Present'
            Enabled   = 'True'
            Direction = 'Inbound'
            Protocol  = 'TCP'
            LocalPort = '80,443,8443'
            Action    = 'Allow'
        }

        # 3. Service optimization
        Service 'AgentHandlerSvc' {
            Name        = 'Trellix Agent Handler'
            StartupType = 'Automatic'
            State       = 'Running'
            DependsOn   = '[Package]InstallAH'
        }
    }
}

# Usage
$nodes = @("ah01.contoso.local","ah02.contoso.local","ah03.contoso.local")
AHDeploymentConfig -NodeName $nodes -OutputPath "C:\DSC\AH"
Start-DscConfiguration -Path "C:\DSC\AH" -Wait -Verbose -Force
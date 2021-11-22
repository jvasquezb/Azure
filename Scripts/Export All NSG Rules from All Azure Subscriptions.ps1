<#
.Synopsis
A script used to export all NSGs rules in all your Azure Subscriptions

.DESCRIPTION
A script used to get the list of all Network Security Groups (NSGs) in all your Azure Subscriptions.
Finally, it will export the report into a csv file in your Azure Cloud Shell storage.

.Notes
Created   : 04-January-2021
Updated   : 16-September-2021
Version   : 3.1
Author    : Charbel Nemnom
Twitter   : @CharbelNemnom
Blog      : https://charbelnemnom.com
Disclaimer: This script is provided "AS IS" with no warranties.
#>

$azSubs = Get-AzSubscription

foreach ( $azSub in $azSubs ) {
    Set-AzContext -Subscription $azSub | Out-Null
    $azSubName = $azSub.Name

    $azNsgs = Get-AzNetworkSecurityGroup 
    
    foreach ( $azNsg in $azNsgs ) {
        # Export custom rules
        Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg | `
            Select-Object @{label = 'NSG Name'; expression = { $azNsg.Name } }, `
            @{label = 'NSG Location'; expression = { $azNsg.Location } }, `
            @{label = 'NSG NetworkInterfaces'; expression = {$azNsg.NetworkInterfaces | Select -Expand Id}}, `
            @{label = 'NSG Subnets'; expression = {$azNsg.Subnets | Select -Expand Id}}, `
            @{label = 'Rule Name'; expression = { $_.Name } }, `
            @{label = 'Source'; expression = { $_.SourceAddressPrefix } }, `
            @{label = 'Source Application Security Group'; expression = { $_.SourceApplicationSecurityGroups.id.Split('/')[-1] } },
            @{label = 'Source Port Range'; expression = { $_.SourcePortRange } }, Access, Priority, Direction, `
            @{label = 'Destination'; expression = { $_.DestinationAddressPrefix } }, `
            @{label = 'Destination Application Security Group'; expression = { $_.DestinationApplicationSecurityGroups.id.Split('/')[-1] } }, `
            @{label = 'Destination Port Range'; expression = { $_.DestinationPortRange } }, `
            @{label = 'Protocol'; expression = { $_.Protocol } }, `
            @{label = 'Resource Group Name'; expression = { $azNsg.ResourceGroupName } } | `
            Export-Csv -Path "$PSScriptRoot\$azSubName-nsg-rules.csv" -NoTypeInformation -Append -force
        
        # Export default rules
        Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg -Defaultrules | `
            Select-Object @{label = 'NSG Name'; expression = { $azNsg.Name } }, `
            @{label = 'NSG Location'; expression = { $azNsg.Location } }, `
            @{label = 'NSG NetworkInterfaces'; expression = {$azNsg.NetworkInterfaces | Select -Expand Id}}, `
            @{label = 'NSG Subnets'; expression = {$azNsg.Subnets | Select -Expand Id}}, `
            @{label = 'Rule Name'; expression = { $_.Name } }, `
            @{label = 'Source'; expression = { $_.SourceAddressPrefix } }, `
            @{label = 'Source Port Range'; expression = { $_.SourcePortRange } }, Access, Priority, Direction, `
            @{label = 'Destination'; expression = { $_.DestinationAddressPrefix } }, `
            @{label = 'Destination Port Range'; expression = { $_.DestinationPortRange } }, `
            @{label = 'Protocol'; expression = { $_.Protocol } }, `
            @{label = 'Resource Group Name'; expression = { $azNsg.ResourceGroupName } } | `
            Export-Csv -Path "$PSScriptRoot\$azSubName-nsg-rules.csv" -NoTypeInformation -Append -force
            # Or you can use the following option to export to a single CSV file and to a local folder on your machine
            # Export-Csv -Path ".\Azure-nsg-rules.csv" -NoTypeInformation -Append -force
      
    }    
}

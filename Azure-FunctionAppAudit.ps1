# CloudCostChefs - Azure Function App Auditor
# A comprehensive Azure Function Apps analysis tool with cost optimization insights
# Version: 1.0
# Author: CloudCostChefs Team
# Description: Analyzes Azure Function Apps across all subscriptions and identifies empty App Service Plans for cost optimization

param(
    [string]$OutputDirectory = ".\CloudCostChefs-Reports",
    [switch]$OpenReportsWhenComplete = $true,
    [switch]$SkipEmptyPlansAnalysis = $false
)

# ============================================================================
# CloudCostChefs Configuration
# ============================================================================
$script:Config = @{
    ScriptName = "CloudCostChefs Azure Function App Auditor"
    Version = "1.0"
    Author = "CloudCostChefs Team"
    Description = "Comprehensive Azure Function Apps analysis with cost optimization insights"
    OutputDirectory = $OutputDirectory
    Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-CloudCostChefs {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "HEADER")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{
        "INFO" = "White"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "HEADER" = "Cyan"
    }
    
    $prefix = switch ($Level) {
        "INFO" { "ℹ️" }
        "SUCCESS" { "✅" }
        "WARNING" { "⚠️" }
        "ERROR" { "❌" }
        "HEADER" { "🏪" }
    }
    
    Write-Host "[$timestamp] $prefix $Message" -ForegroundColor $colors[$Level]
}

function Get-CloudCostChefsHeader {
    return @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🏪 CloudCostChefs 🏪                               ║
║                      Azure Function App Auditor v1.0                        ║
║                                                                              ║
║  📊 Comprehensive Function Apps Analysis                                     ║
║  💰 Cost Optimization Insights                                              ║
║  🔍 Security & Compliance Review                                            ║
║  📈 Empty App Service Plans Detection                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
}

function Initialize-CloudCostChefsEnvironment {
    Write-Host (Get-CloudCostChefsHeader) -ForegroundColor Cyan
    Write-CloudCostChefs "Initializing CloudCostChefs environment..." -Level "HEADER"
    
    # Create output directory
    if (-not (Test-Path $script:Config.OutputDirectory)) {
        New-Item -ItemType Directory -Path $script:Config.OutputDirectory -Force | Out-Null
        Write-CloudCostChefs "Created output directory: $($script:Config.OutputDirectory)" -Level "SUCCESS"
    }
    
    # Verify Azure PowerShell
    try {
        Import-Module Az.Accounts, Az.Resources, Az.Websites -Force -ErrorAction Stop
        Write-CloudCostChefs "Azure PowerShell modules loaded successfully" -Level "SUCCESS"
    }
    catch {
        Write-CloudCostChefs "Failed to load Azure PowerShell modules: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    
    # Check Azure authentication
    $context = Get-AzContext
    if (-not $context) {
        Write-CloudCostChefs "No Azure context found. Please run Connect-AzAccount first." -Level "ERROR"
        throw "Azure authentication required"
    }
    
    Write-CloudCostChefs "Connected to Azure as: $($context.Account.Id)" -Level "SUCCESS"
    Write-CloudCostChefs "Default Subscription: $($context.Subscription.Name)" -Level "INFO"
}

function Get-AppServicePlanCostEstimate {
    param(
        [string]$Tier,
        [string]$Size,
        [int]$Capacity = 1
    )
    
    $baseCost = switch ($Tier) {
        "Free" { 0 }
        "Shared" { 10 }
        "Basic" { 
            switch ($Size) {
                "B1" { 13.50 }
                "B2" { 27.00 }
                "B3" { 54.00 }
                default { 25 }
            }
        }
        "Standard" {
            switch ($Size) {
                "S1" { 73.00 }
                "S2" { 146.00 }
                "S3" { 292.00 }
                default { 150 }
            }
        }
        "Premium" {
            switch ($Size) {
                "P1" { 146.00 }
                "P2" { 292.00 }
                "P3" { 584.00 }
                default { 300 }
            }
        }
        "PremiumV2" {
            switch ($Size) {
                "P1v2" { 73.00 }
                "P2v2" { 146.00 }
                "P3v2" { 292.00 }
                default { 150 }
            }
        }
        "PremiumV3" {
            switch ($Size) {
                "P1v3" { 84.66 }
                "P2v3" { 169.32 }
                "P3v3" { 338.64 }
                default { 200 }
            }
        }
        "ElasticPremium" {
            switch ($Size) {
                "EP1" { 146.00 }
                "EP2" { 292.00 }
                "EP3" { 584.00 }
                default { 300 }
            }
        }
        "Isolated" {
            switch ($Size) {
                "I1" { 438.00 }
                "I2" { 876.00 }
                "I3" { 1752.00 }
                default { 800 }
            }
        }
        "IsolatedV2" {
            switch ($Size) {
                "I1v2" { 358.80 }
                "I2v2" { 717.60 }
                "I3v2" { 1435.20 }
                default { 700 }
            }
        }
        default { 50 }
    }
    
    return [math]::Round($baseCost * $Capacity, 2)
}

function Get-FunctionAppDetails {
    param(
        [object]$FunctionApp,
        [object]$WebAppDetails,
        [object]$AppServicePlanDetails,
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )
    
    # Extract resource group name from the ResourceId
    $resourceGroupName = ""
    if ($FunctionApp.Id) {
        $rgMatch = [regex]::Match($FunctionApp.Id, "/resourceGroups/([^/]+)/")
        if ($rgMatch.Success) {
            $resourceGroupName = $rgMatch.Groups[1].Value
        }
    }
    
    # Extract SKU information
    $skuName = "N/A"
    $skuTier = "N/A"
    $skuSize = "N/A"
    if ($AppServicePlanDetails) {
        $skuName = $AppServicePlanDetails.Sku.Name
        $skuTier = $AppServicePlanDetails.Sku.Tier
        $skuSize = $AppServicePlanDetails.Sku.Size
    }
    
    # Get runtime version
    $runtimeVersion = "N/A"
    if ($WebAppDetails) {
        if ($WebAppDetails.SiteConfig.LinuxFxVersion) {
            $runtimeVersion = $WebAppDetails.SiteConfig.LinuxFxVersion
        }
        elseif ($WebAppDetails.SiteConfig.NetFrameworkVersion) {
            $runtimeVersion = ".NET " + $WebAppDetails.SiteConfig.NetFrameworkVersion
        }
        elseif ($WebAppDetails.SiteConfig.NodeVersion) {
            $runtimeVersion = "Node " + $WebAppDetails.SiteConfig.NodeVersion
        }
        elseif ($WebAppDetails.SiteConfig.PythonVersion) {
            $runtimeVersion = "Python " + $WebAppDetails.SiteConfig.PythonVersion
        }
    }
    
    # Extract owner information from tags
    $applicationOwner = ""
    $tagsToCheck = $FunctionApp.Tags
    if ((-not $tagsToCheck -or $tagsToCheck.Count -eq 0) -and $WebAppDetails) {
        $tagsToCheck = $WebAppDetails.Tags
    }
    
    if ($tagsToCheck -and $tagsToCheck.Count -gt 0) {
        $possibleKeys = @("ApplicationOwner", "Owner", "CreatedBy", "IDSApplicationOwner-Symphony", "idsapplicationowner-symphony")
        
        foreach ($possibleKey in $possibleKeys) {
            if ($tagsToCheck.ContainsKey($possibleKey)) {
                $applicationOwner = $tagsToCheck[$possibleKey]
                break
            }
            
            $matchingKey = $tagsToCheck.Keys | Where-Object { $_ -ieq $possibleKey } | Select-Object -First 1
            if ($matchingKey) {
                $applicationOwner = $tagsToCheck[$matchingKey]
                break
            }
        }
    }
    
    return [PSCustomObject]@{
        'SubscriptionName'        = $SubscriptionName
        'SubscriptionId'          = $SubscriptionId
        'ResourceGroup'           = $resourceGroupName
        'FunctionAppName'         = $FunctionApp.Name
        'FunctionAppState'        = $FunctionApp.State
        'OSType'                  = $FunctionApp.OSType
        'Region'                  = $FunctionApp.Location
        'AppServicePlan'          = if ($FunctionApp.AppServicePlan) { Split-Path $FunctionApp.AppServicePlan -Leaf } else { "N/A" }
        'Runtime'                 = $FunctionApp.Runtime
        'RuntimeVersion'          = $runtimeVersion
        'DefaultHostName'         = $FunctionApp.DefaultHostName
        'Kind'                    = $FunctionApp.Kind
        'SKU_Name'                = $skuName
        'SKU_Tier'                = $skuTier
        'SKU_Size'                = $skuSize
        'NumberOfWorkers'         = if ($WebAppDetails -and $WebAppDetails.SiteConfig.NumberOfWorkers) { $WebAppDetails.SiteConfig.NumberOfWorkers } else { "1" }
        'AlwaysOn'                = if ($WebAppDetails -and $null -ne $WebAppDetails.SiteConfig.AlwaysOn) { $WebAppDetails.SiteConfig.AlwaysOn } else { "N/A" }
        'Use32BitWorkerProcess'   = if ($WebAppDetails -and $null -ne $WebAppDetails.SiteConfig.Use32BitWorkerProcess) { $WebAppDetails.SiteConfig.Use32BitWorkerProcess } else { "N/A" }
        'FtpsState'               = if ($WebAppDetails -and $WebAppDetails.SiteConfig.FtpsState) { $WebAppDetails.SiteConfig.FtpsState } else { "N/A" }
        'HttpsOnly'               = if ($WebAppDetails -and $null -ne $WebAppDetails.HttpsOnly) { $WebAppDetails.HttpsOnly } else { $FunctionApp.HttpsOnly }
        'MinTlsVersion'           = if ($WebAppDetails -and $WebAppDetails.SiteConfig.MinTlsVersion) { $WebAppDetails.SiteConfig.MinTlsVersion } else { "N/A" }
        'Http20Enabled'           = if ($WebAppDetails -and $null -ne $WebAppDetails.SiteConfig.Http20Enabled) { $WebAppDetails.SiteConfig.Http20Enabled } else { "N/A" }
        'ManagedIdentity'         = if ($FunctionApp.Identity) { $FunctionApp.Identity.Type } else { "None" }
        'ApplicationOwner'        = $applicationOwner
        'Tags'                    = if ($FunctionApp.Tags -and $FunctionApp.Tags.Count -gt 0) { ($FunctionApp.Tags | ConvertTo-Json -Compress) -replace '"', '' } else { "" }
        'ResourceId'              = $FunctionApp.Id
        'CollectionTime'          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Get-EmptyAppServicePlans {
    param(
        [array]$AllAppServicePlans,
        [array]$FunctionApps,
        [array]$WebApps,
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )
    
    $emptyPlans = @()
    
    foreach ($appServicePlan in $AllAppServicePlans) {
        try {
            # Check Function Apps using this plan
            $planFunctionApps = $FunctionApps | Where-Object { 
                $_.AppServicePlan -and (Split-Path $_.AppServicePlan -Leaf) -eq $appServicePlan.Name 
            }
            
            # Check Web Apps using this plan
            $planWebApps = $WebApps | Where-Object { 
                $_.ServerFarmId -and (Split-Path $_.ServerFarmId -Leaf) -eq $appServicePlan.Name 
            }
            
            $totalAppsOnPlan = 0
            if ($planFunctionApps) { $totalAppsOnPlan += $planFunctionApps.Count }
            if ($planWebApps) { $totalAppsOnPlan += $planWebApps.Count }
            
            if ($totalAppsOnPlan -eq 0) {
                $estimatedMonthlyCost = Get-AppServicePlanCostEstimate -Tier $appServicePlan.Sku.Tier -Size $appServicePlan.Sku.Size -Capacity $appServicePlan.Sku.Capacity
                
                $emptyPlans += [PSCustomObject]@{
                    'SubscriptionName'        = $SubscriptionName
                    'SubscriptionId'          = $SubscriptionId
                    'ResourceGroup'           = $appServicePlan.ResourceGroup
                    'AppServicePlanName'      = $appServicePlan.Name
                    'Region'                  = $appServicePlan.Location
                    'SKU_Name'                = $appServicePlan.Sku.Name
                    'SKU_Tier'                = $appServicePlan.Sku.Tier
                    'SKU_Size'                = $appServicePlan.Sku.Size
                    'SKU_Family'              = $appServicePlan.Sku.Family
                    'NumberOfWorkers'         = $appServicePlan.Sku.Capacity
                    'EstimatedMonthlyCostUSD' = $estimatedMonthlyCost
                    'EstimatedAnnualCostUSD'  = [math]::Round($estimatedMonthlyCost * 12, 2)
                    'FunctionAppsCount'       = if ($planFunctionApps) { $planFunctionApps.Count } else { 0 }
                    'WebAppsCount'            = if ($planWebApps) { $planWebApps.Count } else { 0 }
                    'TotalAppsCount'          = $totalAppsOnPlan
                    'Status'                  = "Empty - No Applications"
                    'ResourceId'              = $appServicePlan.Id
                    'CollectionTime'          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
        catch {
            Write-CloudCostChefs "Error analyzing App Service Plan '$($appServicePlan.Name)': $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    return $emptyPlans
}

function New-CloudCostChefsHTMLReport {
    param(
        [array]$FunctionAppsData,
        [array]$EmptyPlansData,
        [timespan]$ExecutionTime,
        [int]$SubscriptionCount,
        [array]$ErrorList = @()
    )
    
    $totalApps = $FunctionAppsData.Count
    $totalEmptyPlans = $EmptyPlansData.Count
    $totalEmptyPlansCost = if ($EmptyPlansData.Count -gt 0) { ($EmptyPlansData | Measure-Object -Property EstimatedMonthlyCostUSD -Sum).Sum } else { 0 }
    
    # Calculate statistics
    $stats = @{
        RunningApps = ($FunctionAppsData | Where-Object { $_.FunctionAppState -eq "Running" }).Count
        StoppedApps = ($FunctionAppsData | Where-Object { $_.FunctionAppState -eq "Stopped" }).Count
        WindowsApps = ($FunctionAppsData | Where-Object { $_.OSType -eq "Windows" }).Count
        LinuxApps = ($FunctionAppsData | Where-Object { $_.OSType -eq "Linux" }).Count
        HttpsOnlyApps = ($FunctionAppsData | Where-Object { $_.HttpsOnly -eq $true -or $_.HttpsOnly -eq "True" }).Count
        OldTlsApps = ($FunctionAppsData | Where-Object { $_.MinTlsVersion -eq "1.0" -or $_.MinTlsVersion -eq "1.1" }).Count
        AppsWithOwner = ($FunctionAppsData | Where-Object { $_.ApplicationOwner -ne "" -and $_.ApplicationOwner -ne $null }).Count
        ManagedIdentityApps = ($FunctionAppsData | Where-Object { $_.ManagedIdentity -ne "None" -and $_.ManagedIdentity -ne "" }).Count
    }
    
    # Get top issues - Only flag apps with REAL problems that need immediate attention
    $appsNeedingAttention = $FunctionAppsData | Where-Object { 
        # CRITICAL: Stopped apps (potential service disruption or cost waste)
        $_.FunctionAppState -eq "Stopped" -or 
        
        # CRITICAL: HTTPS not enforced (security vulnerability)
        ($_.HttpsOnly -eq $false -or $_.HttpsOnly -eq "False") -or
        
        # CRITICAL: Old TLS versions (security vulnerability)
        ($_.MinTlsVersion -eq "1.0" -or $_.MinTlsVersion -eq "1.1") -or
        
        # HIGH: FTPS allows all (security risk)
        $_.FtpsState -eq "AllAllowed"
        
        # REMOVED: Missing owner tag - this is governance, not an immediate technical issue
        # Applications can function perfectly without owner tags, it's just for governance
        
    } | Sort-Object @{Expression={
        $score = 0
        if ($_.FunctionAppState -eq "Stopped") { $score += 20 }                           # Highest - service impact
        if ($_.HttpsOnly -eq $false -or $_.HttpsOnly -eq "False") { $score += 15 }        # High - security vulnerability  
        if ($_.MinTlsVersion -eq "1.0" -or $_.MinTlsVersion -eq "1.1") { $score += 10 }   # Medium - security vulnerability
        if ($_.FtpsState -eq "AllAllowed") { $score += 5 }                               # Lower - security risk
        $score
    }; Descending=$true } | Select-Object -First 10
    
    # Generate HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudCostChefs - Azure Function Apps Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1); 
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #4f46e5, #7c3aed);
            color: white; 
            padding: 40px; 
            text-align: center; 
            position: relative;
        }
        .header::before {
            content: '🏪';
            font-size: 60px;
            position: absolute;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
        }
        .header h1 { 
            margin: 60px 0 20px 0; 
            font-size: 32px; 
            font-weight: 700;
        }
        .header .subtitle { 
            font-size: 18px; 
            opacity: 0.9; 
            margin-bottom: 10px;
        }
        .header .timestamp { 
            font-size: 14px; 
            opacity: 0.8; 
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 40px; 
        }
        .summary-card { 
            background: linear-gradient(135deg, #f8fafc, #e2e8f0);
            padding: 25px; 
            border-radius: 12px; 
            text-align: center; 
            border-left: 5px solid #4f46e5;
            transition: transform 0.2s ease;
        }
        .summary-card:hover { transform: translateY(-5px); }
        .summary-card .number { 
            font-size: 36px; 
            font-weight: bold; 
            color: #4f46e5; 
            margin-bottom: 10px;
        }
        .summary-card .label { 
            color: #64748b; 
            font-size: 14px; 
            font-weight: 500;
        }
        .content { padding: 0 40px 40px 40px; }
        .section { 
            margin: 40px 0; 
            padding: 30px; 
            border: 1px solid #e2e8f0; 
            border-radius: 12px; 
            background: #f8fafc; 
        }
        .section h2 { 
            color: #1e293b; 
            margin-bottom: 20px; 
            font-size: 24px;
            border-bottom: 3px solid #4f46e5; 
            padding-bottom: 10px; 
        }
        .cost-alert { 
            background: linear-gradient(135deg, #dc2626, #b91c1c); 
            color: white; 
            padding: 25px; 
            border-radius: 12px; 
            text-align: center; 
            margin: 30px 0; 
            font-weight: bold;
            font-size: 18px;
        }
        .cost-savings { 
            background: linear-gradient(135deg, #059669, #047857); 
            color: white; 
            padding: 25px; 
            border-radius: 12px; 
            text-align: center; 
            margin: 30px 0; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
        }
        th, td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #e2e8f0;
        }
        th { 
            background: #4f46e5; 
            color: white; 
            font-weight: 600; 
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover { 
            background: #f1f5f9; 
        }
        .status-good { color: #059669; font-weight: bold; }
        .status-warning { color: #d97706; font-weight: bold; }
        .status-critical { color: #dc2626; font-weight: bold; }
        .footer { 
            background: #1e293b; 
            color: white; 
            padding: 30px; 
            text-align: center; 
        }
        .footer .brand { 
            font-size: 24px; 
            font-weight: bold; 
            margin-bottom: 10px;
        }
        .footer .tagline { 
            font-size: 16px; 
            opacity: 0.8; 
        }
        .action-items {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .action-items h3 {
            color: #92400e;
            margin-bottom: 15px;
        }
        .action-items ul {
            color: #92400e;
            margin-left: 20px;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 20px 0;
        }
        @media (max-width: 768px) {
            .grid-2 { grid-template-columns: 1fr; }
            .summary-grid { grid-template-columns: 1fr; }
            .header, .content { padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CloudCostChefs</h1>
            <div class="subtitle">Azure Function Apps Analysis Report</div>
            <div class="timestamp">Generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy at HH:mm:ss')</div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">$totalApps</div>
                <div class="label">Function Apps</div>
            </div>
            <div class="summary-card">
                <div class="number">$SubscriptionCount</div>
                <div class="label">Subscriptions</div>
            </div>
            <div class="summary-card">
                <div class="number">$($stats.AppsWithOwner)</div>
                <div class="label">Apps with Owner</div>
            </div>
            <div class="summary-card">
                <div class="number">$($appsNeedingAttention.Count)</div>
                <div class="label">Need Attention</div>
            </div>
            <div class="summary-card">
                <div class="number">$totalEmptyPlans</div>
                <div class="label">Empty Plans</div>
            </div>
            <div class="summary-card">
                <div class="number">`$$($totalEmptyPlansCost)</div>
                <div class="label">Monthly Waste</div>
            </div>
        </div>
        
        <div class="content">
"@

    if ($totalEmptyPlans -gt 0) {
        $htmlContent += @"
            <div class="cost-alert">
                🚨 COST OPTIMIZATION ALERT: `$$($totalEmptyPlansCost)/month (`$$($totalEmptyPlansCost * 12)/year) being wasted on $totalEmptyPlans empty App Service Plans!
            </div>
            
            <div class="section">
                <h2>💰 Empty App Service Plans (Immediate Cost Savings)</h2>
                <div class="action-items">
                    <h3>URGENT: Delete These Unused Plans</h3>
                    <p>These App Service Plans have NO applications but are still costing money:</p>
                    <ul>
                        <li><strong>Monthly Waste:</strong> `$$totalEmptyPlansCost USD</li>
                        <li><strong>Annual Waste:</strong> `$$($totalEmptyPlansCost * 12) USD</li>
                        <li><strong>Risk Level:</strong> LOW - No applications will be affected</li>
                        <li><strong>Action:</strong> Delete immediately for instant savings</li>
                    </ul>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Plan Name</th>
                            <th>Subscription</th>
                            <th>Resource Group</th>
                            <th>SKU</th>
                            <th>Region</th>
                            <th>Monthly Cost</th>
                            <th>Annual Cost</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($plan in ($EmptyPlansData | Sort-Object EstimatedMonthlyCostUSD -Descending | Select-Object -First 20)) {
            $htmlContent += @"
                        <tr>
                            <td>$($plan.AppServicePlanName)</td>
                            <td>$($plan.SubscriptionName)</td>
                            <td>$($plan.ResourceGroup)</td>
                            <td>$($plan.SKU_Tier) ($($plan.SKU_Size))</td>
                            <td>$($plan.Region)</td>
                            <td class="status-critical">`$$($plan.EstimatedMonthlyCostUSD)</td>
                            <td class="status-critical">`$$($plan.EstimatedAnnualCostUSD)</td>
                        </tr>
"@
        }
        
        $htmlContent += @"
                    </tbody>
                </table>
            </div>
"@
    } else {
        $htmlContent += @"
            <div class="cost-savings">
                ✅ EXCELLENT: No empty App Service Plans found! Your resources are well optimized.
            </div>
"@
    }

    if ($totalApps -gt 0) {
        $htmlContent += @"
            <div class="section">
                <h2>📊 Function Apps Overview</h2>
                <div class="grid-2">
                    <div>
                        <h4>Application States</h4>
                        <ul>
                            <li><span class="status-good">Running:</span> $($stats.RunningApps) apps</li>
                            <li><span class="status-warning">Stopped:</span> $($stats.StoppedApps) apps</li>
                        </ul>
                        
                        <h4>Platform Distribution</h4>
                        <ul>
                            <li><strong>Windows:</strong> $($stats.WindowsApps) apps</li>
                            <li><strong>Linux:</strong> $($stats.LinuxApps) apps</li>
                        </ul>
                    </div>
                    <div>
                        <h4>Security & Compliance</h4>
                        <ul>
                            <li><span class="status-good">HTTPS-Only:</span> $($stats.HttpsOnlyApps) apps</li>
                            <li><span class="status-critical">Old TLS:</span> $($stats.OldTlsApps) apps</li>
                            <li><span class="status-good">Managed Identity:</span> $($stats.ManagedIdentityApps) apps</li>
                        </ul>
                        
                        <h4>Governance</h4>
                        <ul>
                            <li><span class="status-good">With Owner:</span> $($stats.AppsWithOwner) apps</li>
                            <li><span class="status-warning">No Owner:</span> $($totalApps - $stats.AppsWithOwner) apps</li>
                        </ul>
                        <p style="font-size: 12px; color: #666; margin-top: 10px;">
                            <em>Note: Missing owner tags are governance issues, not technical problems.</em>
                        </p>
                    </div>
                </div>
            </div>
"@

        if ($appsNeedingAttention.Count -gt 0) {
            $htmlContent += @"
            <div class="section">
                <h2>⚠️ Function Apps Requiring Immediate Technical Attention</h2>
                <div class="action-items">
                    <h3>Critical Issues Found</h3>
                    <p>These Function Apps have <strong>technical security or operational issues</strong> that require immediate attention:</p>
                    <ul>
                        <li><span class="status-critical">🔴 CRITICAL:</span> Stopped apps (service disruption or cost waste)</li>
                        <li><span class="status-critical">🔴 CRITICAL:</span> HTTPS not enforced (security vulnerability)</li>
                        <li><span class="status-critical">🔴 CRITICAL:</span> Old TLS versions 1.0/1.1 (security vulnerability)</li>
                        <li><span class="status-warning">🟡 HIGH:</span> FTPS allows all connections (security risk)</li>
                    </ul>
                    <p><strong>Note:</strong> Governance issues like missing owner tags are tracked separately and don't appear here.</p>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Function App Name</th>
                            <th>Subscription</th>
                            <th>State</th>
                            <th>HTTPS Only</th>
                            <th>TLS Version</th>
                            <th>FTPS State</th>
                            <th>Priority</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            
            foreach ($app in $appsNeedingAttention) {
                $stateClass = if ($app.FunctionAppState -eq "Running") { "status-good" } else { "status-critical" }
                $httpsClass = if ($app.HttpsOnly -eq $true -or $app.HttpsOnly -eq "True") { "status-good" } else { "status-critical" }
                $tlsClass = if ($app.MinTlsVersion -eq "1.0" -or $app.MinTlsVersion -eq "1.1") { "status-critical" } else { "status-good" }
                $ftpsClass = if ($app.FtpsState -eq "AllAllowed") { "status-warning" } else { "status-good" }
                
                # Determine priority and issues
                $issues = @()
                $priority = "LOW"
                if ($app.FunctionAppState -eq "Stopped") { 
                    $issues += "Stopped"
                    $priority = "CRITICAL"
                }
                if ($app.HttpsOnly -eq $false -or $app.HttpsOnly -eq "False") { 
                    $issues += "HTTP Allowed"
                    $priority = "CRITICAL"
                }
                if ($app.MinTlsVersion -eq "1.0" -or $app.MinTlsVersion -eq "1.1") { 
                    $issues += "Old TLS"
                    $priority = "CRITICAL"
                }
                if ($app.FtpsState -eq "AllAllowed") { 
                    $issues += "FTPS Risk"
                    if ($priority -eq "LOW") { $priority = "HIGH" }
                }
                
                $priorityClass = switch ($priority) {
                    "CRITICAL" { "status-critical" }
                    "HIGH" { "status-warning" }
                    default { "status-good" }
                }
                
                $htmlContent += @"
                        <tr>
                            <td>$($app.FunctionAppName)</td>
                            <td>$($app.SubscriptionName)</td>
                            <td><span class="$stateClass">$($app.FunctionAppState)</span></td>
                            <td><span class="$httpsClass">$($app.HttpsOnly)</span></td>
                            <td><span class="$tlsClass">$($app.MinTlsVersion)</span></td>
                            <td><span class="$ftpsClass">$($app.FtpsState)</span></td>
                            <td><span class="$priorityClass">$priority</span></td>
                        </tr>
"@
            }
            
            $htmlContent += @"
                    </tbody>
                </table>
                
                <div class="action-items">
                    <h3>Immediate Actions Required</h3>
                    <ul>
                        <li><strong>🔴 CRITICAL:</strong> Enable HTTPS-only: <code>Set-AzWebApp -Name "AppName" -HttpsOnly `$true</code></li>
                        <li><strong>🔴 CRITICAL:</strong> Upgrade TLS to 1.2+: <code>Set-AzWebApp -Name "AppName" -MinTlsVersion "1.2"</code></li>
                        <li><strong>🔴 CRITICAL:</strong> Review stopped apps - restart or delete if no longer needed</li>
                        <li><strong>🟡 HIGH:</strong> Disable FTPS or set to "FtpsOnly": <code>Set-AzWebApp -Name "AppName" -FtpsState "FtpsOnly"</code></li>
                    </ul>
                </div>
            </div>
"@
        }
    }

    # Add runtime and subscription analysis if we have apps
    if ($totalApps -gt 0) {
        $runtimeGroups = $FunctionAppsData | Where-Object { $_.Runtime -and $_.Runtime -ne "" } | Group-Object Runtime | Sort-Object Count -Descending
        $subscriptionGroups = $FunctionAppsData | Group-Object SubscriptionName | Sort-Object Count -Descending
        
        $htmlContent += @"
            <div class="section">
                <h2>📈 Distribution Analysis</h2>
                <div class="grid-2">
                    <div>
                        <h4>Top Runtimes</h4>
                        <table>
                            <thead>
                                <tr><th>Runtime</th><th>Count</th></tr>
                            </thead>
                            <tbody>
"@
        
        foreach ($runtime in ($runtimeGroups | Select-Object -First 10)) {
            $htmlContent += "<tr><td>$($runtime.Name)</td><td>$($runtime.Count)</td></tr>"
        }
        
        $htmlContent += @"
                            </tbody>
                        </table>
                    </div>
                    <div>
                        <h4>Apps by Subscription</h4>
                        <table>
                            <thead>
                                <tr><th>Subscription</th><th>Count</th></tr>
                            </thead>
                            <tbody>
"@
        
        foreach ($sub in ($subscriptionGroups | Select-Object -First 10)) {
            $htmlContent += "<tr><td>$($sub.Name)</td><td>$($sub.Count)</td></tr>"
        }
        
        $htmlContent += @"
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"@
    }

    # Execution summary
    $htmlContent += @"
            <div class="section">
                <h2>📋 Execution Summary</h2>
                <div class="grid-2">
                    <div>
                        <h4>Analysis Details</h4>
                        <ul>
                            <li><strong>Execution Time:</strong> $([math]::Round($ExecutionTime.TotalMinutes, 2)) minutes</li>
                            <li><strong>Subscriptions Scanned:</strong> $SubscriptionCount</li>
                            <li><strong>Function Apps Found:</strong> $totalApps</li>
                            <li><strong>Empty Plans Found:</strong> $totalEmptyPlans</li>
                        </ul>
                    </div>
                    <div>
                        <h4>Cost Impact</h4>
                        <ul>
                            <li><strong>Monthly Waste:</strong> `$totalEmptyPlansCost</li>
                            <li><strong>Annual Savings Potential:</strong> `$($totalEmptyPlansCost * 12)</li>
                            $(if ($ErrorList.Count -gt 0) { "<li><strong>Errors:</strong> $($ErrorList.Count) encountered</li>" } else { "<li><strong>Status:</strong> No errors encountered</li>" })
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <div class="brand">🏪 CloudCostChefs</div>
            <div class="tagline">Serving up cost optimization insights, one cloud resource at a time!</div>
            <div style="margin-top: 15px; font-size: 14px; opacity: 0.7;">
                Generated by CloudCostChefs Azure Function App Auditor v1.0
            </div>
        </div>
    </div>
</body>
</html>
"@

    return $htmlContent
}

# ============================================================================
# Main Execution
# ============================================================================

function Start-CloudCostChefsFunctionAppAudit {
    $startTime = Get-Date
    $functionAppsData = @()
    $emptyPlansData = @()
    $errorList = @()
    
    try {
        # Initialize environment
        Initialize-CloudCostChefsEnvironment
        
        # Get all subscriptions
        Write-CloudCostChefs "Discovering Azure subscriptions..." -Level "INFO"
        $subscriptions = Get-AzSubscription
        
        if (-not $subscriptions) {
            throw "No subscriptions found. Please ensure you have proper Azure access."
        }
        
        Write-CloudCostChefs "Found $($subscriptions.Count) subscription(s) to analyze" -Level "SUCCESS"
        
        # Process each subscription
        $subscriptionCounter = 0
        foreach ($subscription in $subscriptions) {
            $subscriptionCounter++
            try {
                Write-CloudCostChefs "Processing subscription $subscriptionCounter/$($subscriptions.Count): $($subscription.Name)" -Level "INFO"
                
                # Set subscription context
                $context = Set-AzContext -Subscription $subscription.Id -ErrorAction Stop
                
                # Get Function Apps
                $functionApps = @(Get-AzFunctionApp -ErrorAction SilentlyContinue)
                
                if ($functionApps.Count -eq 0) {
                    Write-CloudCostChefs "No Function Apps found in subscription: $($subscription.Name)" -Level "WARNING"
                } else {
                    Write-CloudCostChefs "Found $($functionApps.Count) Function App(s)" -Level "SUCCESS"
                    
                    # Process each Function App
                    foreach ($fnApp in $functionApps) {
                        try {
                            # Extract resource group
                            $resourceGroupName = ""
                            if ($fnApp.Id) {
                                $rgMatch = [regex]::Match($fnApp.Id, "/resourceGroups/([^/]+)/")
                                if ($rgMatch.Success) {
                                    $resourceGroupName = $rgMatch.Groups[1].Value
                                }
                            }
                            
                            # Get detailed information
                            $webAppDetails = $null
                            $appServicePlanDetails = $null
                            
                            if ($resourceGroupName) {
                                $webAppDetails = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $fnApp.Name -ErrorAction SilentlyContinue
                                
                                if ($fnApp.AppServicePlan) {
                                    $planName = Split-Path $fnApp.AppServicePlan -Leaf
                                    $appServicePlanDetails = Get-AzAppServicePlan -ResourceGroupName $resourceGroupName -Name $planName -ErrorAction SilentlyContinue
                                }
                            }
                            
                            # Create Function App details object
                            $appDetails = Get-FunctionAppDetails -FunctionApp $fnApp -WebAppDetails $webAppDetails -AppServicePlanDetails $appServicePlanDetails -SubscriptionName $subscription.Name -SubscriptionId $subscription.Id
                            $functionAppsData += $appDetails
                            
                        }
                        catch {
                            $errorMsg = "Error processing Function App '$($fnApp.Name)': $($_.Exception.Message)"
                            Write-CloudCostChefs $errorMsg -Level "WARNING"
                            $errorList += $errorMsg
                        }
                    }
                }
                
                # Analyze empty App Service Plans (if not skipped)
                if (-not $SkipEmptyPlansAnalysis) {
                    Write-CloudCostChefs "Analyzing App Service Plans for cost optimization..." -Level "INFO"
                    
                    $allAppServicePlans = @(Get-AzAppServicePlan -ErrorAction SilentlyContinue)
                    $allWebApps = @(Get-AzWebApp -ErrorAction SilentlyContinue)
                    
                    if ($allAppServicePlans.Count -gt 0) {
                        $emptyPlans = Get-EmptyAppServicePlans -AllAppServicePlans $allAppServicePlans -FunctionApps $functionApps -WebApps $allWebApps -SubscriptionName $subscription.Name -SubscriptionId $subscription.Id
                        $emptyPlansData += $emptyPlans
                        
                        if ($emptyPlans.Count -gt 0) {
                            $wasteCost = ($emptyPlans | Measure-Object -Property EstimatedMonthlyCostUSD -Sum).Sum
                            Write-CloudCostChefs "Found $($emptyPlans.Count) empty App Service Plans wasting `$wasteCost/month" -Level "WARNING"
                        }
                    }
                }
                
            }
            catch {
                $errorMsg = "Error processing subscription '$($subscription.Name)': $($_.Exception.Message)"
                Write-CloudCostChefs $errorMsg -Level "ERROR"
                $errorList += $errorMsg
            }
        }
        
        # Calculate execution time
        $endTime = Get-Date
        $executionTime = $endTime - $startTime
        
        # Generate reports
        Write-CloudCostChefs "Generating CloudCostChefs reports..." -Level "INFO"
        
        $timestamp = $script:Config.Timestamp
        $csvPath = Join-Path $script:Config.OutputDirectory "CloudCostChefs-FunctionApps-$timestamp.csv"
        $emptyPlansCsvPath = Join-Path $script:Config.OutputDirectory "CloudCostChefs-EmptyPlans-$timestamp.csv"
        $htmlPath = Join-Path $script:Config.OutputDirectory "CloudCostChefs-FunctionApps-Report-$timestamp.html"
        
        # Export CSV files
        if ($functionAppsData.Count -gt 0) {
            $functionAppsData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-CloudCostChefs "Function Apps CSV exported: $csvPath" -Level "SUCCESS"
        }
        
        if ($emptyPlansData.Count -gt 0) {
            $emptyPlansData | Export-Csv -Path $emptyPlansCsvPath -NoTypeInformation -Encoding UTF8
            Write-CloudCostChefs "Empty Plans CSV exported: $emptyPlansCsvPath" -Level "SUCCESS"
        }
        
        # Generate HTML report
        $htmlContent = New-CloudCostChefsHTMLReport -FunctionAppsData $functionAppsData -EmptyPlansData $emptyPlansData -ExecutionTime $executionTime -SubscriptionCount $subscriptions.Count -ErrorList $errorList
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-CloudCostChefs "HTML report generated: $htmlPath" -Level "SUCCESS"
        
        # Display summary
        Write-CloudCostChefs "Analysis Complete! 🎉" -Level "HEADER"
        Write-Host ""
        Write-Host "📊 CLOUDCOSTCHEFS SUMMARY" -ForegroundColor Cyan
        Write-Host "=========================" -ForegroundColor Cyan
        Write-Host "Function Apps Found: $($functionAppsData.Count)" -ForegroundColor White
        Write-Host "Subscriptions Scanned: $($subscriptions.Count)" -ForegroundColor White
        Write-Host "Empty App Service Plans: $($emptyPlansData.Count)" -ForegroundColor White
        
        if ($emptyPlansData.Count -gt 0) {
            $totalWaste = ($emptyPlansData | Measure-Object -Property EstimatedMonthlyCostUSD -Sum).Sum
            Write-Host "Monthly Cost Waste: $totalWaste USD" -ForegroundColor Red
            Write-Host "Annual Savings Potential: $($totalWaste * 12) USD" -ForegroundColor Red
        } else {
            Write-Host "Cost Optimization Status: ✅ EXCELLENT" -ForegroundColor Green
        }
        
        Write-Host "Execution Time: $([math]::Round($executionTime.TotalMinutes, 2)) minutes" -ForegroundColor White
        Write-Host ""
        Write-Host "📁 Reports Generated:" -ForegroundColor Yellow
        if ($functionAppsData.Count -gt 0) { Write-Host "   • $csvPath" -ForegroundColor Gray }
        if ($emptyPlansData.Count -gt 0) { Write-Host "   • $emptyPlansCsvPath" -ForegroundColor Gray }
        Write-Host "   • $htmlPath" -ForegroundColor Gray
        
        # Open reports if requested
        if ($OpenReportsWhenComplete) {
            Write-CloudCostChefs "Opening HTML report..." -Level "INFO"
            Start-Process $htmlPath
        }
        
        # Final recommendations
        if ($emptyPlansData.Count -gt 0) {
            Write-Host ""
            Write-Host "💡 IMMEDIATE COST SAVINGS OPPORTUNITY!" -ForegroundColor Yellow
            Write-Host "   Delete $($emptyPlansData.Count) empty App Service Plans to save $($totalWaste * 12) USD/year" -ForegroundColor Yellow
            Write-Host "   Risk: LOW (no applications will be affected)" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-CloudCostChefs "Critical error during analysis: $($_.Exception.Message)" -Level "ERROR"
        Write-CloudCostChefs "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        throw
    }
}

# ============================================================================
# Script Entry Point
# ============================================================================

# Run the analysis
Start-CloudCostChefsFunctionAppAudit

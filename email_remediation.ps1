# version 0.1 #
# Define the Application (Client) ID and Secret
$ApplicationClientId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
$ApplicationClientSecret = ''
$TenantId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'

# Convert the Client Secret to a Secure String
$SecureClientSecret = ConvertTo-SecureString -String $ApplicationClientSecret -AsPlainText -Force

# Create a PSCredential Object Using the Client ID and Secure Client Secret
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationClientId, $SecureClientSecret

# Connect to Microsoft Graph Using the Tenant ID and Client Secret Credential
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

####
#Defender query to get Messages we are interested in based on initial NetworkMessageID.
#foreach loop takes the NetworkMessageID from that email, grabs the sender address, then queries all messages sent by that sender in the past X Days.
#then makes a graph query against user inboxes to get the "id" field which is required to delete those emails.
#change the NetworkMessageId below

$defenderquery = (Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body '{ "Query": "let _maliciousSender =EmailEvents| where NetworkMessageId == guid(''c6fb4b65-c89f-4387-fe54-08dd9c6e302c'')| distinct SenderFromAddress;EmailEvents| where SenderFromAddress in (_maliciousSender)|where TimeGenerated > ago(7d)|sort by TimeGenerated desc" }').results

#build array

$results = @()

  foreach ($_ in $defenderquery) {
  	$getGraphMessageInfo = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($_.RecipientEmailAddress)/messages?`$filter=internetMessageId eq '$($_.InternetMessageId)'").value

  $properties = @{
    SenderDisplayName  = $getGraphMessageInfo.sender.emailAddress.name
    SenderEmailAddress = $getGraphMessageInfo.sender.emailAddress.address
    Recipients         = $getGraphMessageInfo.toRecipients.emailaddress.address
    SubjectLine        = $getGraphMessageInfo.subject
    internetMessageId  = $getGraphMessageInfo.internetMessageId
    id                 = $getGraphMessageInfo.id
  }
$results += $properties
}

#write results to console

$results

#delete each email from $results

foreach ($_ in $results) {
  Remove-MgUserMessage -MessageId $($_.id) -UserId $($_.Recipients)
}
cls
#----------------------------------------------------------------------
# Modified by: Clayton Kramer clayton.kramer@gmail.com
# Lasted Modified: Tue 01 Feb 2011 04:44:24 PM EST 
#
# Based on original script Levente Veres (bergermanus)
# Contact: http://my.bergersoft.net
# Link: http://my.bergersoft.net/2009/05/26/how-to-send-password-expire-alert-to-ad-users-with-powershell/
# Description: The current script send Alert for users before they password
# expires. You can set some values to configure this script.
#-----------------------------------------------------------------------

import-module ActiveDirectory

# Set the max day before expiration alert
$max_alert = 7

# Set STMP values
$smtpServer = "localhost"
$smtpFrom = "it-shop@my.company.com"

# Administrator email (comma deliminate multiple addresses)
$adminEmail = "it-shop@my.company.com"

# Organization Name
$orgName = "My Company"

# Function to send email to each user
function send_email_user ($remainingDays, $email, $name, $account, $smtpServer, $smtpFrom)
{
	$today = Get-Date
	$dateExpires = [DateTime]::Now.AddDays($remainingDays) ;
	$smtpClient = new-object system.net.mail.smtpClient
	$mailMessage = New-Object system.net.mail.mailmessage
	$smtpClient.Host = $smtpServer
	$mailMessage.from = $smtpFrom
	$mailmessage.To.add($email)
	$mailMessage.Subject = "$name, your domain password expires soon."
	$mailMessage.IsBodyHtml = $true
	
$body = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <style type="text/css">
BODY{font-family: Verdana, Calibri, Arial;font-size: 12px;}
    </style>
    <title></title>
  </head>
  <body>
    <b>Dear $name</b>,
    <p>This is a reminder that your network password for account <b>$account</b> will expire in <b>$remainingDays days</b>. If you do not change it by <b>$dateExpires</b>, you will not be able to connect to the $orgName network.</p>
	<b>Policy</b>
    <p>Passwords must meet the following minimum requirements:</p>
    <ul>
      <li>Not contain the your account name or parts of the your full name that exceed two consecutive characters</li>
      <li>Be at least seven characters in length</li>
      <li>Cannot be a previously used password</li>
    </ul>
    <p> Contain characters from three of the following four categories:</p>
    <ul>
      <li>English uppercase characters (A through Z)</li>
      <li>English lowercase characters (a through z)</li>
      <li>Base 10 digits (0 through 9)</li>
      <li>Non-alphabetic characters (for example, !, $, #, %)</li>
    </ul><b>Instructions</b>
    <p>Follow the steps below to change your password:</p>
    <p>Windows Users</p>
    <ol>
      <li>Press CTRL+ALT+DEL</li>
      <li>On the screen that came choose <i>Change password</i></li>
      <li>Type in your old password and then type the new one (be advised you cannot use one of the previously used passwords)</li>
      <li>After the change is complete you will be prompted with information that passwor has been changed</li>
    </ol>
    <p>Linux Users</p>
    <ol>
      <li>Open a terminal</li>
      <li>Execute the <i>passwd</i> command.</li>
      <li>Enter your current password.</li>
      <li>Type your new password (be advised you cannot use one of the previously used passwords)</li>
      <li>Provide the new password again at the confirmation prompt</li>
    </ol>
    <p>For questions or comments please contact your system administrator.</p>
    <hr noshade>
    <p>Generated on : $today</p>
  </body>
</html>
"@

	$mailMessage.Body = $body
	$smtpClient.Send($mailmessage)
	#$body | out-File "usermsg.html"
}

# Send report for Admins
function send_email_admin($body, $smtpServer, $smtpFrom, $adminEmail)
{

	$smtpClient = new-object system.net.mail.smtpClient
	$mailMessage = New-Object system.net.mail.mailmessage
	$smtpClient.Host = $smtpServer
	$mailMessage.from = $smtpFrom
	
	$mailMessage.Subject = "[Report] Domain Password Expiration"
	$mailMessage.IsBodyHtml = $true
	$mailMessage.Body = $body
	$mailMessage.Body += "`n" 

	foreach ($a in $adminEmail.Split(",")){
		$mailMessage.To.add($a)
	}
	
	$smtpClient.Send($mailMessage)
}

# Search for the active directory users with following conditions
# 1. Is in USER category
# 2. Is loged in more that 1 times for eliminate the system accounts
# 3. Eliminate the Disbaled Accounts

$userlist = @()
$strFilter = "(&(objectCategory=User)(logonCount>=1)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.PageSize = 1000
$objSearcher.Filter = $strFilter
$colResults = $objSearcher.FindAll();

# Get the default domain password policy (Powershell 2.0)
$passPolicy = Get-ADDefaultDomainPasswordPolicy
$MaxPwdAge = [INT]$passPolicy.MaxPasswordAge.TotalDays

foreach ($objResult in $colResults)
{
	$objItem = $objResult.Properties;
	if ( $objItem.mail.gettype.IsInstance -eq $True)
	{		
		#Transform the DateTime readable
		$userLogon = [datetime]::FromFileTime($objItem.lastlogon[0])
		$result =  $objItem.pwdlastset
		$userPwdLastSet = [datetime]::FromFileTime($result[0])

		#calculate the difference in Day
		$diffDate = [INT]([DateTime]::Now - $userPwdLastSet).TotalDays;
		
		# Get users that are about to expire but no those that are already expired
		# This way the script can run once every day without spamming users who might be on leave.
		if ((($MaxPwdAge - $diffDate) -le $max_alert) -and ($diffDate -gt 0)) {
			$selectedUser = New-Object psobject
			$selectedUser | Add-Member NoteProperty -Name "Name" -Value  $objItem.name[0]
			$selectedUser | Add-Member NoteProperty -Name "Account" -Value  $objItem.userprincipalname[0]
			$selectedUser | Add-Member NoteProperty -Name "Email" -Value   $objItem.mail[0]
			
			$emailLink = "<a href='mailto:" + $objItem.mail[0] + "'>" +$objItem.mail[0] + "</a>"
			$selectedUser | Add-Member NoteProperty -Name "EmailLink" -Value $emailLink
			$selectedUser | Add-Member NoteProperty -Name "LastLogon" -Value $userLogon
			$selectedUser | Add-Member NoteProperty -Name "LastPwdSet" -Value $userPwdLastSet
			$selectedUser | Add-Member NoteProperty -Name "Ellapsed" -Value $diffDate
			$selectedUser | Add-Member NoteProperty -Name "Remaining" -Value ($MaxPwdAge-$diffDate)
			$userlist += $selectedUser
		}
	}
}

# Send email for each user
foreach ($user in $userlist )
{
	send_email_user $user.Remaining $user.Email $user.Name $user.Account $smtpServer $smtpFrom
}

# Send email for Admins in reporting format if there are any users to report
if ( $userlist.Count -gt 0 )
{

$today = Get-Date
$style = @"
<style type="text/css">
body{background-color:#FFFFFF;font: 10pt/1.5 Verdana, Calibri, Arial;}
h1, h2, h3, h4, h5, h6 {
	line-height: 120%; 
	margin: 0 0 0.5em 0;
	color: #252525;
}
table {
	border: 1px solid #CCC;
	font-size:12px;
	white-space: nowrap;
}
th {
	border: 1px solid #CCC;
	padding: 10px;
	background-color:#FF4040;
	height: 40px;
}
td{
	border: 1px solid #CCC;
	padding: 10px;
	background-color:#FEFEFE;
	height: 40px }
</style>
"@

$body = @"
<h2>AD password expiration status report</h2>
<hr noshade/>
<p>The following users have passwords nearing expiration.</p>
<p>Generated: $today</p>
"@	

# Convert the userlist into an HTML report and email to administrators
$bodyme = $userlist | Select-Object Name, EmailLink, LastLogon, LastPwdSet, Ellapsed, Remaining |  Sort-Object "RemainingDay" |  ConvertTo-Html -Title "Active Directory password Status" -Body $body -head $style  | % {$_.replace("&lt;","<").replace("&gt;",">").replace("EmailLink","Email")} | foreach {$_ -replace "<table>", "</table><table cellspacing=0 width=90%>"}
send_email_admin $bodyme $smtpServer $smtpFrom $adminEmail
#$bodyme | out-File "output.html"

} 

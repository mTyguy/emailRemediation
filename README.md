Project with the goal of deleting suspected or known phishing emails from M365 user inboxes.

The builtin Defender for Office365 plan 2 rule "A user clicked through to a potentially malicious URL" provides a NetworkMessageId that can be utilized to find the sender and automate removal of all emails they sent. 
https://learn.microsoft.com/en-us/defender-xdr/alert-policies?view=o365-worldwide#threat-management-alert-policies

  1) Run a KQL query to enummerate all emails the Sender sent to the domain in the past X days utilizing a single NetworkMessageId.
  2) MSGraph call to find the required ID parameter for those emails.
  3) Utilize the ID parameter to delete those emails.

Requires:
1) EmailEvents table in Defender
2) API permissions: ThreatHunting.Read.All & Mail.ReadWrite

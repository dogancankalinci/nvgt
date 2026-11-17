# mail_message
An email message to send with an smtp_client object.

`mail_message();`

## Remarks:
Set the sender, add recipients, set the subject and content, then pass the message to an smtp_client's send_message method.

Header values, header names and addresses must not contain line breaks. The sender, a recipient's address or name, the subject, a header's name or value, the reply_to, message_id, in_reply_to, references, return_receipt_to and disposition_notification_to properties, a content or media type, an attachment's name or path and an inline attachment's content ID are refused when they contain a carriage return (`\r`), a line feed (`\n`) or a NUL character: they would otherwise start a new header line in the message (or a new command in the conversation with the server) that the script never meant to send. A refused value leaves the message as it was, a method that returns a value returns false or an empty string, and the last_error property says what was refused. Header names must also be printable ASCII characters without spaces or colons.

package proxy

const (
	TokenPageStartFmt = `
<!DOCTYPE html>
<html>
<body>

<h2>Generate Token for User %s</h2>

<form action="%s" method="post">
  <input type="submit" value="Generate">
</form>
</body>
</html>

`

	TokenPageSuccessFmt = `
<!DOCTYPE html>
<html>
<body>

<h2>Generate Token for User %s</h2>

<form action="%s" method="post">
  <input type="submit" value="Generate">
</form>
<br>
Your new token is: <code style="background-color:#cecece">%s</code>
<br>
Please copy it, as you will not be able to see it again after closing this page.
</body>
</html>

`

	TokenPageFailureFmt = `
<!DOCTYPE html>
<html>
<body>

<h2>Generate Token for User %s</h2>

<form action="%s" method="post">
  <input type="submit" value="Generate">
</form>
<br>
There was an error generating your new token. Your original token has not been changed. Contact an administrator.
</body>
</html>

`
)

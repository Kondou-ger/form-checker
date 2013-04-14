<!DOCTYPE html>
<html>
<body>
<?php
# Work arround PHP's magic quotes
if ( in_array( strtolower( ini_get( 'magic_quotes_gpc' ) ), array( '1', 'on' ) ) )
{
	$_POST = array_map( 'stripslashes', $_POST );
	$_GET = array_map( 'stripslashes', $_GET );
}

# Invulnerable SQL-field
if ($_POST["nick"] == "" && $_POST["pass"] == ""): ?>
<form method="POST" action="test-site.php">
	<input type="text" name=\"nick\">
	<input type="password" name="pass">
	<input type="submit" value="Login">
</form>
<?php else: ?>
Wrong user!
<?php endif; ?>
<hr>

<?php # Invulnerable SQL and/or XSS-field
if ($_GET["searchstring"] == ""): ?>
<form method="GET" action="test-site.php">
	<input type="text" name="searchstring">
	<input type="submit" value="Search">
</form>
<?php else: ?>
Result:<br>
Result 1<br><br>
Result 2<br><br>
Result 3<br><br>
Result 4<br><br>
Result 5<br><br>
Result 6<br><br>
Result 7<br><br>
Result 8<br><br>
<? endif; ?>
<hr>

<?php # Vurnerable XSS-field (GET)
echo("XSS GET<br>");
if ($_GET["getechotext"] == ""): ?>
<form method="GET" action="test-site.php">
	<input type="text" name="getechotext" value="Text to echo">
	<input type="submit">
</form>
<?php else:
Your text was: " . $_GET["getechotext"] . ". <a href=\"test-site.php\">Again?</a>");
endif;
?>
<hr>

<?php # Vulnerable XSS-field (POST)
echo("XSS POST<br>");
if ($_POST["postechotext"] == ""): ?>
<form method="POST" action="test-site.php">
	<input type="text" name="postechotext" value="Text to echo">
	<input type="submit">
</form>
<?php else:
	echo("Your text was:" . $_POST["postechotext"] . ". <a href=\"test-site.php\">Again?</a>");
endif; ?>
<hr>

<?php # Vulnerable SQL-field (GET)
echo("SQL GET<br>");
if ($_GET["getsearch"] == ""): ?>
<form method="GET" action="test-site.php">
	<input type="text" name="getsearch">
	<input type="submit" value="Search">
</form>
<?php else:
	# Connect to database
	mysql_connect("localhost", "root", "") or die("No connection possible.");
	mysql_select_db("test");
	$query = mysql_query("SELECT read FROM sqlinjection WHERE read LIKE '%". $_GET["getsearch"] . "%';");
	echo("Result:<br>");
	while ($row = mysql_fetch_row($query))
		echo($row[0] . "<br>");
endif; ?>
<hr>

<?php # Vulnerable SQL-field (POST)
echo("SQL POST<br>");
if ($_POST["postsearch"] == ""): ?>
<form method="POST" action="test-site.php">
	<input type="text" name="postsearch">
	<input type="submit" value="Search">
</form>
<?php else:
	# Connect to database
	mysql_connect("localhost", "root", "") or die("No connection possible.");
	mysql_select_db("test");
	$query = mysql_query("SELECT read FROM sqlinjection WHERE read LIKE '%". $_GET["postsearch"] . "%';");
	echo("Result:<br>");
	while ($row = mysql_fetch_row($query))
		echo($row[0] . "<br>");
endif; ?>
</body>
</html>

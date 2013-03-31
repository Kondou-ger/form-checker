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
if ($_POST["nick"] == "" && $_POST["pass"] == "")
	echo("<form method=\"POST\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"nick\">\n
		<input type=\"password\" name=\"pass\">\n
		<input type=\"submit\" value=\"Login\">\n
		</form>\n");
else
	echo("Wrong user!");

echo("<hr>");

# Invulnerable SQL and/or XSS-field
if ($_GET["searchstring"] == "")
	echo("<form method=\"GET\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"searchstring\">\n
		<input type=\"submit\" value=\"Search\">\n
		</form>\n");
else
	echo("Result:<br>\n
		Result 1<br><br>\n
		Result 2<br><br>\n
		Result 3<br><br>\n
		Result 4<br><br>\n
		Result 5<br><br>\n
		Result 6<br><br>\n
		Result 7<br><br>\n
		Result 8<br><br>\n");

echo("<hr>");

# Vurnerable XSS-field (GET)
echo("XSS GET<br>");
if ($_GET["getechotext"] == "")
	echo("<form method=\"GET\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"getechotext\" value=\"Text to echo\">\n
		<input type=\"submit\" value=\"Send\">\n
		</form>\n");
else
	echo("Your text was: " . $_GET["getechotext"] . ". <a href=\"test-site.php\">Again?</a>");

echo("<hr>");

# Vulnerable XSS-field (POST)
echo("XSS POST<br>");
if ($_POST["postechotext"] == "")
	echo("<form method=\"POST\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"postechotext\" value=\"Text to echo\">\n
		<input type=\"submit\" value=\"Send\">\n
		</form>\n");
else
	echo("Your text was:" . $_POST["postechotext"] . ". <a href=\"test-site.php\">Again?</a>");

echo("<hr>");

# Vulnerable SQL-field (GET)
echo("SQL GET<br>");
if ($_GET["getsearch"] == "")
	echo("<form method=\"GET\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"getsearch\">\n
		<input type=\"submit\" value=\"Search\">\n
		</form>\n");
else {
	# Connect to database
	mysql_connect("localhost", "root", "") or die("No connection possible.");
	mysql_select_db("test");
	$query = mysql_query("SELECT read FROM sqlinjection WHERE read LIKE '%". $_GET["getsearch"] . "%';");
	echo("Result:<br>");
	while ($row = mysql_fetch_row($query))
		echo($row[0] . "<br>");
	}
		
echo("<hr>");

# Vulnerable SQL-field (POST)
echo("SQL POST<br>");
if ($_POST["postsearch"] == "")
	echo("<form method=\"POST\" action=\"test-site.php\">\n
		<input type=\"text\" name=\"postsearch\">\n
		<input type=\"submit\" value=\"Search\">\n
		</form>\n");
else {
	# Connect to database
	mysql_connect("localhost", "root", "") or die("No connection possible.");
	mysql_select_db("test");
	$query = mysql_query("SELECT read FROM sqlinjection WHERE read LIKE '%". $_GET["postsearch"] . "%';");
	echo("Result:<br>");
	while ($row = mysql_fetch_row($query))
		echo($row[0] . "<br>");
}

?>
</body>
</html>

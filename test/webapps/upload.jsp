<%@ page language="java" %>
<html>
    <head><title>Display file upload form to the user</title></head>  
    <body> 
        <form enctype="multipart/form-data" action="single_upload_page.jsp" method=POST>
            <p><b>PROGRAM FOR UPLOADING THE FILE</b></p>
            <p><b>Choose the file To Upload:</b> <input name="F1" type="file"></p>
            <p><input type="submit" value="Send File"></p>
        </form>
    </body>
</html>

function vulnerable() {
    eval("alert(1)");
    document.write("<p>Hello</p>");
    document.execCommand("copy");
}
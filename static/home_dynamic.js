function open_tab(evt, tab_name) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tab_name).style.display = "block";
    evt.currentTarget.className += " active";

}
function onload(){
  var tabcontent = document.getElementsByClassName("tabcontent");
  tabcontent[0].style.display="block"
  var tablinks = document.getElementsByClassName("tablinks");
  tablinks[0].className +=" active";

}


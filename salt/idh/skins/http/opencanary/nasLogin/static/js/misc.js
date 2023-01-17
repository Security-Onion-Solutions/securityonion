"use strict";

var montharray = new Array();
montharray[0] = "Jan";
montharray[1] = "Feb";
montharray[2] = "Mar";
montharray[3] = "Apr";
montharray[4] = "May";
montharray[5] = "Jun";
montharray[6] = "Jul";
montharray[7] = "Aug";
montharray[8] = "Sep";
montharray[9] = "Oct";
montharray[10] = "Nov";
montharray[11] = "Dec";

var dayarray = new Array();
dayarray[0] = "Sun";
dayarray[1] = "Mon";
dayarray[2] = "Tue";
dayarray[3] = "Wed";
dayarray[4] = "Thu";
dayarray[5] = "Fri";
dayarray[6] = "Sat";


function updateTime() {
var d = new Date();
var h = d.getHours();
var m = d.getMinutes();
m = new String(m);
if (m.length == 1)
    m = "0" + m;

var pms = "AM";
if (h > 12)
{
pms = "PM"
h = h % 12;
}

document.getElementById('ext-comp-1007').innerHTML = h + ":" + m + '<span class="time-tag">' + pms + '</span>';

var month = montharray[d.getMonth()];
var wkday = dayarray[d.getDay()];
var day = d.getDate();

document.getElementById('ext-comp-1008').innerHTML = wkday + ", " + month + " " + day;

}

updateTime();
window.setInterval(updateTime, 2000);


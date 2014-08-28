 var CertificateAuth = function(filePath, filePassword){
        cordova.exec(function(winParam) {}, 
            function(error) {}, 
            "CertificateAuth",
            "setPathAndPassword", 
            [filePath, filePassword]);
    };

module.exports = CertificateAuth
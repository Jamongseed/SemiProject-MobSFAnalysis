// bypass.js (no DEX, overload-safe, guarded-proxy)
(function(){
  function log(tag, m){ try{ console.log("[BYPASS]["+tag+"] "+(m||"")); }catch(e){} }
  function safe(desc, f){ try{ f(); log("OK", desc); } catch(e){ log("FAIL", desc+" : "+e); } }

  Java.perform(function () {
    try {
      var Application = Java.use('android.app.Application');
      Application.attach.overload('android.content.Context').implementation = function (ctx) {
        try { installEarlyHooks(ctx); } catch (e) { console.log("[BYPASS][attach] "+e); }
        return this.attach(ctx);
      };
    } catch (e) {}

    // --- Helper: 호출 스택에 우리 앱이 있는지 검사 ---
    function calledByApp() {
      try {
        var Ex = Java.use('java.lang.Exception');
        var st = Ex.$new().getStackTrace();
        for (var i = 0; i < st.length; i++) {
          var cn = '' + st[i].getClassName();
          if (cn.indexOf('com.ldjSxw.heBbQd') !== -1 || cn.indexOf('com.bosetn.oct16m') !== -1) {
            return true;
          }
        }
      } catch(e) {}
      return false;
    }

    function installEarlyHooks(ctx) {
      // (B) 앱이 스스로 죽이는 루트 차단
      try {
        var Runtime = Java.use('java.lang.Runtime');
        var System = Java.use('java.lang.System');
        var Proc = Java.use('android.os.Process');

        Runtime.exit.implementation = function(code){ console.log("[BYPASS] Runtime.exit("+code+") blocked"); };
        System.exit.implementation  = function(code){ console.log("[BYPASS] System.exit("+code+") blocked"); };
        Proc.killProcess.implementation = function(pid){ console.log("[BYPASS] killProcess("+pid+") blocked"); };
      } catch(e){}

      // (C) NetworkSecurityPolicy: 평문 허용
      try {
        var NSP = Java.use('android.security.NetworkSecurityPolicy');
        if (NSP && NSP.isCleartextTrafficPermitted) {
          NSP.isCleartextTrafficPermitted.overload().implementation = function(){ return true; };
          NSP.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(d){ return true; };
        }
      } catch(e){}

      // (D) libc의 strstr로 'frida' 탐지 차단
      try {
        var strstr = Module.findExportByName("libc.so", "strstr");
        if (strstr) {
          Interceptor.attach(strstr, {
            onEnter: function(args){
              try{
                var needle = args[1].readCString()||"";
                if (needle.indexOf("frida") !== -1 || needle.indexOf("gum-js") !== -1) {
                  args[1] = Memory.allocUtf8String(" harmless ");
                }
              }catch(e){}
            }
          });
        }
      } catch(e){}
    }

    // ===== Generic hardening =====
    safe("Locale.getLanguage -> 'ko'", function () {
      var Locale = Java.use("java.util.Locale");
      Locale.getLanguage.implementation = function () { return "ko"; };
    });

    safe("String contains/indexOf/equals filters", function () {
      var S = Java.use("java.lang.String");
      var deny = ["test-keys","supersu","magisk","xposed","busybox","frida","genymotion","vbox","goldfish"];
      S.contains.overload('java.lang.CharSequence').implementation = function (cs) {
        var s = cs ? cs.toString().toLowerCase() : "";
        if (deny.some(function(k){ return s.indexOf(k)!==-1; })) return false;
        return this.contains.call(this, cs);
      };
      S.indexOf.overload('java.lang.String').implementation = function (t) {
        var s = (t||"").toLowerCase();
        if (s.indexOf("goldfish")!==-1 || s.indexOf("genymotion")!==-1 || s.indexOf("vbox")!==-1) return -1;
        return this.indexOf.call(this, t);
      };
      S.equals.overload('java.lang.Object').implementation = function (o) {
        var other = (o?(""+o):"").toLowerCase();
        if (other==="tun0"||other==="ppp0"||other.indexOf("frida")!==-1) return false;
        return this.equals.call(this, o);
      };
    });

    safe("File.exists root paths -> false", function () {
      var File = Java.use('java.io.File');
      var BAD = new Set([
        "/system/app/Superuser.apk","/sbin/su","/system/bin/su","/system/xbin/su",
        "/data/local/xbin/su","/data/local/bin/su","/system/sd/xbin/su",
        "/system/bin/failsafe/su","/data/local/su"
      ]);
      File.exists.implementation = function () {
        try{ if(BAD.has(this.getAbsolutePath())) return false; }catch(e){}
        return this.exists.call(this);
      };
    });

    safe("Debug.isDebuggerConnected -> false", function () {
      var D = Java.use("android.os.Debug");
      D.isDebuggerConnected.implementation = function(){ return false; };
      D.waitingForDebugger.implementation = function(){ return false; };
    });

    // ===== Proxy detect bypass (guarded) =====
    // 앱 코드에서만 프록시 숨김, 그 외(라이브러리/시스템)는 원본 유지 → 프록시 경유 트래픽 캡처 가능
    safe("System.getProperty proxy guarded", function () {
      var Sys = Java.use("java.lang.System");
      Sys.getProperty.overload('java.lang.String').implementation = function (k) {
        var v = this.getProperty.call(this, k);
        if (!k) return v;
        var kk = (''+k).toLowerCase();
        if ((kk === 'http.proxyhost' || kk === 'http.proxyport' ||
             kk === 'https.proxyhost' || kk === 'https.proxyport') && calledByApp()) {
          return null;
        }
        return v;
      };
    });

    safe("Settings.Global.getString http_proxy guarded", function () {
      var G = Java.use("android.provider.Settings$Global");
      G.getString.overload('android.content.ContentResolver','java.lang.String')
        .implementation = function (cr, name) {
          var ret = this.getString.call(this, cr, name);
          try {
            var key = (''+name).toLowerCase();
            if ((key.indexOf('http_proxy') !== -1 || key.indexOf('global_http_proxy') !== -1) && calledByApp()) {
              return "";
            }
          } catch(e) {}
          return ret;
        };
    });

    safe("android.net.Proxy guarded", function () {
      var P = Java.use("android.net.Proxy");
      if (P.getDefaultHost) P.getDefaultHost.implementation = function(){
        return calledByApp() ? null : this.getDefaultHost.call(this);
      };
      if (P.getHost) P.getHost.implementation = function(ctx){
        return calledByApp() ? null : this.getHost.call(this, ctx);
      };
      if (P.getPort) P.getPort.implementation = function(ctx){
        return calledByApp() ? 0 : this.getPort.call(this, ctx);
      };
      if (P.getDefaultPort) P.getDefaultPort.implementation = function(){
        return calledByApp() ? 0 : this.getDefaultPort.call(this);
      };
    });

    safe("android.net.ProxyInfo guarded", function () {
      try {
        var PI = Java.use('android.net.ProxyInfo');
        if (PI.getHost) PI.getHost.implementation = function(){
          return calledByApp() ? null : this.getHost.call(this);
        };
        if (PI.getPort) PI.getPort.implementation = function(){
          return calledByApp() ? 0 : this.getPort.call(this);
        };
      } catch(e){}
    });

    // ===== SSL Pinning / Trust chain bypass =====
    safe("OkHttp CertificatePinner.check -> no-op", function () {
      try {
        var P = Java.use('okhttp3.CertificatePinner');
        if (P.check.overload('java.lang.String','java.util.List')) {
          P.check.overload('java.lang.String','java.util.List').implementation = function (h, certs){ return; };
        }
        if (P.check.overload('java.lang.String','java.security.cert.Certificate')) {
          P.check.overload('java.lang.String','java.security.cert.Certificate').implementation = function (h, c){ return; };
        }
      } catch(e1){
        try {
          var OP = Java.use('com.squareup.okhttp.CertificatePinner');
          if (OP.check.overload('java.lang.String','[Ljava.security.cert.Certificate;')) {
            OP.check.overload('java.lang.String','[Ljava.security.cert.Certificate;').implementation = function (h, arr){ return; };
          }
          if (OP.check.overload('java.lang.String','java.util.List')) {
            OP.check.overload('java.lang.String','java.util.List').implementation = function (h, l){ return; };
          }
        } catch(e2){}
      }
    });

    safe("TrustManager.checkServerTrusted -> no-op (all overloads)", function () {
      var names = [
        'com.android.org.conscrypt.TrustManagerImpl',
        'com.android.org.conscrypt.X509TrustManagerImpl',
        'sun.security.ssl.X509TrustManagerImpl'
      ];
      names.forEach(function(nm){
        try {
          var TM = Java.use(nm);
          var sigs = [
            ['[Ljava.security.cert.X509Certificate;','java.lang.String'],
            ['[Ljava.security.cert.X509Certificate;','java.lang.String','java.lang.String'],
            ['[Ljava.security.cert.X509Certificate;','java.lang.String','javax.net.ssl.SSLSession'],
            ['[Ljava.security.cert.X509Certificate;','java.lang.String','java.net.Socket'],
            ['[Ljava.security.cert.X509Certificate;','java.lang.String','javax.net.ssl.SSLEngine']
          ];
          sigs.forEach(function(sig){
            try {
              if (TM.checkServerTrusted.overload.apply(TM.checkServerTrusted, sig)) {
                TM.checkServerTrusted.overload.apply(TM.checkServerTrusted, sig)
                  .implementation = function () { return arguments[0]; };
              }
            } catch(e){}
          });
          log("OK", "[SSL] patched "+nm+".checkServerTrusted (present overloads)");
        } catch(e){}
      });
    });

    safe("HostnameVerifier.verify -> true", function () {
      var targets = [
        'okhttp3.internal.tls.OkHostnameVerifier',
        'okhttp3.internal.tls.BasicHostnameVerifier',
        'com.squareup.okhttp.internal.tls.OkHostnameVerifier'
      ];
      targets.forEach(function (cls) {
        try {
          var Hv = Java.use(cls);
          if (Hv.verify && Hv.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')) {
            Hv.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
              .implementation = function (host, sess) { return true; };
            log("OK", "[SSL] HostnameVerifier patched: "+cls);
          }
        } catch (e) {}
      });
      try {
        var Abs = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        if (Abs.verify && Abs.verify.overload('java.lang.String','javax.net.ssl.SSLSession')) {
          Abs.verify.overload('java.lang.String','javax.net.ssl.SSLSession')
            .implementation = function(h,s){ return true; };
        }
      } catch(e){}
    });

    safe("WebViewClient.onReceivedSslError -> proceed", function () {
      var WVC = Java.use('android.webkit.WebViewClient');
      WVC.onReceivedSslError.implementation = function (view, handler, error) {
        try { handler.proceed(); } catch(e){}
      };
    });

    log("READY");
  });
})();

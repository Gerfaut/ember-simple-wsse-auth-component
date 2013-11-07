// ============================================================================
// Project:   Simple Wsse Auth - Simple Wsse Authentication for Ember.js
// Copyright: ©2013 Christophe Leemans and contributors
//            Forked from Simple Auth, by Marco Otte-Witte 
//            ember.js is ©2011-2013 Tilde Inc.
// License:   Licensed under MIT license
//            See https://raw.github.com/gerfaut/ember-simple-wsse-auth/master/LICENSE
// ============================================================================


// Version: 0.0.2-4-g5d78395317
// Last commit: 5d78395317 (2013-11-07 22:49:56 +0100)


(function() {
/*global CryptoJS*/

Ember.SimpleWsseAuth = {};
Ember.SimpleWsseAuth.BuildXWsseHeader = function(session) {
    var username = session.get('username');
    var passwordEncoded = session.get('passwordEncoded');
    var nonce = this.GenerateNonce();
    var createdDate = this.GenerateCreatedDate();
    var passwordDigest = this.GeneratePasswordDigest(nonce, createdDate, passwordEncoded);
    return 'UsernameToken Username="' + username + '", PasswordDigest="' + passwordDigest + '", Nonce="' + nonce + '", Created="' + createdDate + '"';
};
Ember.SimpleWsseAuth.GenerateNonce = function() {
    var nonce = Math.random().toString(36).substring(2);
    return CryptoJS.enc.Utf8.parse(nonce).toString(CryptoJS.enc.Base64);
};
Ember.SimpleWsseAuth.GeneratePasswordDigest = function(nonce, createdDate, passwordEncoded) {
    var nonce_64 = CryptoJS.enc.Base64.parse(nonce);
    var _sha1 = CryptoJS.SHA1(nonce_64.concat(CryptoJS.enc.Utf8.parse(createdDate).concat(CryptoJS.enc.Utf8.parse(passwordEncoded))));
    var result = _sha1.toString(CryptoJS.enc.Base64);
    return result;
    //return CryptoJS.SHA1(CryptoJS.enc.Base64.parse(nonce) + createdDate + passwordEncoded).toString(CryptoJS.enc.Base64);
};
Ember.SimpleWsseAuth.EncodePassword = function(password, salt) {
    var salted = password + '{' + salt + '}';
    var passwordEncoded = CryptoJS.SHA512(salted);
    for(var i = 1; i < this.passwordEncodingIterations; i++) { //TODO use webworker
	passwordEncoded = CryptoJS.SHA512(passwordEncoded.concat(CryptoJS.enc.Utf8.parse(salted)));
    }
    return this.passwordEncodingAsBase64 ? passwordEncoded.toString(CryptoJS.enc.Base64) : passwordEncoded;
};
Ember.SimpleWsseAuth.GenerateCreatedDate = function() {
    return new Date().toISOString();
};
Ember.SimpleWsseAuth.setup = function(app, options) {
  options = options || {};
  this.routeAfterLogin = options.routeAfterLogin || 'index';
  this.routeAfterLogout = options.routeAfterLogout || 'index';
  this.loginRoute = options.loginRoute || 'login';
  this.logoutRoute = options.logoutRoute || 'logout';
  this.serverSaltRoute = options.serverSaltRoute || '/salt/{username}';
  this.serverCheckAccessRoute = options.serverCheckAccessRoute || '/check-access';
  this.passwordEncodingIterations = options.passwordEncodingIterations || 5000;
  this.passwordEncodingAsBase64 = options.passwordEncodingAsBase64 === 'false' ? false : true;

  var session = Ember.SimpleWsseAuth.Session.create();
  app.register('simple_wsse_auth:session', session, { instantiate: false, singleton: true });
  
  Ember.$.each(['model', 'controller', 'view', 'route'], function(i, component) {
    app.inject(component, 'session', 'simple_wsse_auth:session');
  });

  Ember.$.ajaxPrefilter(function(options, originalOptions, jqXHR) {
    if (!jqXHR.crossDomain && session.get('isAuthValid')) {
      jqXHR.setRequestHeader('Authorization',  'Authorization profile="UsernameToken"');
      jqXHR.setRequestHeader('X-WSSE',  Ember.SimpleWsseAuth.BuildXWsseHeader(session));
    }
  });
};

})();



(function() {
Ember.SimpleWsseAuth.Session = Ember.Object.extend({
  init: function() {
    this._super();
    this.set('username', sessionStorage.username);
    this.set('passwordEncoded', sessionStorage.passwordEncoded);
    if(sessionStorage.username !== undefined && sessionStorage.passwordEncoded !== undefined) {
      this.set('accountRestored', true);
    }
  },
  setup: function(serverSalt, password) {
    var salt = (serverSalt.session || {}).salt;
    var username = (serverSalt.session || {}).username;
    this.set('passwordEncoded', Ember.SimpleWsseAuth.EncodePassword(password, salt));
    this.set('username', username);
    this.set('accountRestored', true);
  },
  didAccessChecked: function() {
    this.set('accessChecked', true);
  },
  destroy: function() {
    this.set('username', undefined);
    this.set('passwordEncoded', undefined);
    this.set('accessChecked', undefined);
    this.set('accountRestored', undefined);
  },
  isAuthValid: Ember.computed('username', 'passwordEncoded', function() {
    return !Ember.isEmpty(this.get('username')) && !Ember.isEmpty(this.get('passwordEncoded'));
  }),
  isAuthenticated: Ember.computed('username', 'passwordEncoded', 'accessChecked', function() {
    return !Ember.isEmpty(this.get('username')) && this.get('accessChecked') && this.get('isAuthValid');
  }),
  authDataObserver: Ember.observer(function() {
    var username = this.get('username');
    if (Ember.isEmpty(username)) {
      delete sessionStorage.username;
    } else {
      sessionStorage.username = this.get('username');
    }
    
    var passwordEncoded = this.get('passwordEncoded');
    if (Ember.isEmpty(passwordEncoded)) {
      delete sessionStorage.passwordEncoded;
    } else {
      sessionStorage.passwordEncoded = this.get('passwordEncoded');
    }
  }, 'passwordEncoded', 'username')
});
})();



(function() {
Ember.SimpleWsseAuth.AuthenticatedRouteMixin = Ember.Mixin.create({
  beforeModel: function(transition) {
    if (!this.get('session.isAuthenticated')) {
      this.redirectToLogin(transition);
    }
  },
  redirectToLogin: function(transition) {
    this.set('session.attemptedTransition', transition);
    this.transitionTo(Ember.SimpleWsseAuth.loginRoute);
  }
});
})();



(function() {
Ember.SimpleWsseAuth.SaltControllerMixin = Ember.Mixin.create({
  test:true,
  actions: {
    login: function() {
      var self = this;
      var data = this.getProperties('username');
      var secret = this.getProperties('password');
      if (!Ember.isEmpty(data.username)) {
        var saltRoute = Ember.SimpleWsseAuth.serverSaltRoute;
        if(saltRoute.indexOf('{username}') !== 0) {
            saltRoute = saltRoute.replace('{username}', data.username);
        }
        Ember.$.ajax(saltRoute).then(function(response) {
          self.get('session').setup(response, secret.password);
          self.send('checkAccess');
        }, function() {
          Ember.tryInvoke(self, 'loginFailed', arguments);
        });
      }
    },
    checkAccess: function() {
      if(this.get('session.accountRestored')) {
        var self = this;
        var checkAccessRoute = Ember.SimpleWsseAuth.serverCheckAccessRoute;
        Ember.$.ajax(checkAccessRoute).then(function(response) {
          self.get('session').didAccessChecked();
          var attemptedTransition = self.get('session.attemptedTransition');
          if (attemptedTransition) {
            attemptedTransition.retry();
            self.set('session.attemptedTransition', null);
          } else {
            self.transitionToRoute(Ember.SimpleWsseAuth.routeAfterLogin);
          }
        }, function() {
          Ember.tryInvoke(self, 'loginFailed', arguments);
        });
      }
    }
  }
});
})();



(function() {
Ember.SimpleWsseAuth.LogoutRouteMixin = Ember.Mixin.create({
  beforeModel: function() {
    this.get('session').destroy();
    this.transitionTo(Ember.SimpleWsseAuth.routeAfterLogout);
  }
});
})();



(function() {

})();


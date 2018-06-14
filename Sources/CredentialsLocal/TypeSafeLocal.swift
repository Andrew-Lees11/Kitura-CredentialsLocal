import Foundation
import Kitura
import KituraSession
import Credentials
import LoggerAPI
import KituraContracts


/// Protocol for implementing local authentication using typeSafeMiddleware.
/// ### Usage Example: ###
/// private let users = ["John" : "12345", "Mary" : "qwerasdf"]
///
/// public struct MyLocal: TypeSafeLocal {
///     public static var loginRoute: String = "/typesafelogin"
///
///     public typealias inputForm = MyForm
///
///     public static func verifyPassword(formData: MyForm, sessionId: String, callback: @escaping (MyLocal?) -> Void) {
///         if (users[formData.username] == formData.password) {
///             callback(MyLocal(sessionId: sessionId, id: formData.username))
///         } else {
///             callback(nil)
///         }
///     }
///
///     public let sessionId: String
///
///     public var id: String
///
///     public static var store: Store?
///
///     public static var sessionCookie: SessionCookie = SessionCookie(name: "hello", secret: "world")
///
/// }
///
/// public struct MyForm: Codable {
///     let username: String
///     let password: String
/// }
///
/// MyLocal.registerLogin(router: router)
/// router.get("/private") { (authProfile: MyLocal, respondWith: (MyLocal?, RequestError?) -> Void) in
///     respondWith(authProfile, nil)
/// }
public protocol TypeSafeLocal: TypeSafeCredentials, CodableSession {
    associatedtype inputForm: Codable
    static func verifyPassword(formData: inputForm, sessionId: String, callback: @escaping (Self?) -> Void) -> Void
    static var loginRoute: String { get }
    static var failureRedirect: String? { get }
    static var successRedirect: String? { get }
}

extension TypeSafeLocal {
    
    /// The name of the authentication provider (defaults to "HTTPLocal")
    public var provider: String {
        return "HTTPLocal"
    }
    
    /// The route that you post the form data to login (defaults to "/login/local")
    public static var loginRoute: String {
        return "/login/local"
    }
    
    /// If failureRedirect is set, you will be redirected to this route on failed authentication (defaults to nil)
    public static var failureRedirect: String? {
        return nil
    }
    
    /// If successRedirect is set, you will be redirected to this route from the loginRoute on authentication (defaults to nil)
    public static var successRedirect: String? {
        return nil
    }
    
    /// Function to authenticate a user from a URLEncoded form sent via a POST request.
    public static func authenticate(request: RouterRequest, response: RouterResponse, onSuccess: @escaping (Self) -> Void, onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void, onSkip: @escaping (HTTPStatusCode?, [String : String]?) -> Void) {
        
        getOrCreateSession(request: request, response: response) { (userProfile, sessionId, error) in
            if let userProfile = userProfile {
                return onSuccess(userProfile)
            }
            guard let sessionId = sessionId else {
                // failed to create session
                if let failureRedirect = failureRedirect {
                    let _ = try? response.redirect(failureRedirect)
                    return
                } else {
                    return onFailure(.internalServerError, nil)
                }
            }
            guard let inputForm = try? request.read(as: inputForm.self) else {
                if let failureRedirect = failureRedirect {
                    let _ = try? response.redirect(failureRedirect)
                    return
                } else {
                    return onSkip(.badRequest, nil)
                }
            }
            verifyPassword(formData: inputForm, sessionId: sessionId) { (userProfile) in
                guard let userProfile = userProfile else {
                    if let failureRedirect = failureRedirect {
                        let _ = try? response.redirect(failureRedirect)
                        return
                    } else {
                        return onFailure(.unauthorized, nil)
                    }
                }
                userProfile.save()
                if(userProfile.addCookie(request: request, response: response)) {
                    return onSuccess(userProfile)
                } else {
                    if let failureRedirect = failureRedirect {
                        let _ = try? response.redirect(failureRedirect)
                        return
                    } else {
                        return onFailure(.internalServerError, nil)
                    }
                }
            }
        }
    }
    
    /// Function to register the login route for local authentication.
    /// this route is created on POST requests to `loginRoute`
    /// and call `authenticate` on the recieved form.
    public static func registerLogin(router: Router) {
        router.post(Self.loginRoute) { request, response, next in
            Self.authenticate(request: request, response: response,
                              onSuccess: { (userProfile) in
                                if let successRedirect = successRedirect {
                                    let _ = try? response.redirect(successRedirect)
                                } else {
                                    response.send(userProfile)
                                    let _ = try? response.end()
                                }
                              }, onFailure: { (error, headers) in
                                response.status(error ?? .unauthorized)
                                let _ = try? response.end()
                              }, onSkip: { (error, headers) in
                                response.status(error ?? .unauthorized)
                                let _ = try? response.end()
                              })
        }
    }
}

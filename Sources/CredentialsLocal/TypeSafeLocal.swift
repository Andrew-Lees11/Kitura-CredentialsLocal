import Foundation
import Kitura
import KituraSession
import Credentials
import LoggerAPI
import KituraContracts


/// Protocol for implementing local authentication using typeSafeMiddleware.
/// ### Usage Example: ###
/// public struct MyLocal: TypeSafeLocal {
///     public let sessionId: String
///
///     public typealias inputForm = MyForm
///
///     public static func verifyPassword(formData: MyForm, sessionId: String, callback: @escaping (MyLocal?) -> Void) {
///         callback(MyLocal(sessionId: sessionId, id: formData.username))
///     }
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
public protocol TypeSafeLocal: TypeSafeCredentials, CodableSession {
    associatedtype inputForm: Codable
    static func verifyPassword(formData: inputForm, sessionId: String, callback: @escaping (Self?) -> Void) -> Void
}

extension TypeSafeLocal {
    
    /// The name of the authentication provider (defaults to "HTTPLocal")
    public var provider: String {
        return "HTTPLocal"
    }
    
    public static func authenticate(request: RouterRequest, response: RouterResponse, onSuccess: @escaping (Self) -> Void, onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void, onSkip: @escaping (HTTPStatusCode?, [String : String]?) -> Void) {
        
        getOrCreateSession(request: request, response: response) { (userProfile, sessionId, error) in
            if let userProfile = userProfile {
                return onSuccess(userProfile)
            }
            guard let sessionId = sessionId else {
                // failed to create session
                return onFailure(nil, nil)
            }
            guard let inputForm = try? request.read(as: inputForm.self) else {
                return onSkip(nil, nil)
            }
            verifyPassword(formData: inputForm, sessionId: sessionId) { (userProfile) in
                guard let userProfile = userProfile else {
                    return onFailure(nil, nil)
                }
                userProfile.save()
                if(userProfile.addCookie(request: request, response: response)) {
                    return onSuccess(userProfile)
                } else {
                    return onFailure(nil, nil)
                }
            }
        }
    }
}

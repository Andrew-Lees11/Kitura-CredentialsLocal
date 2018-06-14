import Foundation
import XCTest

import Kitura
import KituraNet
import KituraSession
import KituraContracts
import Credentials
import LoggerAPI

@testable import CredentialsLocal

class TestTypeSafeLocal : XCTestCase {
    
    static var allTests : [(String, (TestTypeSafeLocal) -> () throws -> Void)] {
        return [
            ("testNoCredentials", testNoCredentialsSimple),
            ("testBadCredentials", testBadCredentialsSimple),
            ("testGoodCredentials", testGoodCredentialsSimple),
        ]
    }
    
    override func setUp() {
        doSetUp()
    }
    
    override func tearDown() {
        doTearDown()
    }
    
    let host = "127.0.0.1"
    
    let router = TestTypeSafeLocal.setupCodableRouter()
    
    func testNoCredentialsSimple() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", host: self.host, path: "/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.badRequest, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            })
        }
    }
    
    func testNoCredentialsRequest() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", host: self.host, path: "/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.badRequest, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            })
        }
    }
    
    func testBadCredentialsSimple() {
        // Good username, bad password
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=John&password=wrongPassword")
            })
        }
        
        
        // Good password, bad username
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=Maria&password=qwerasdf")
            })
        }
    }
    
    func testBadCredentialsRequest() {
        // Good username, bad password
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=John&password=wrongPassword")
            })
        }
        
        
        // Good password, bad username
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=Maria&password=qwerasdf")
            })
        }
    }
    
    func testGoodCredentialsSimple() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/typesafelogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let stringBody = try response?.readString(),
                        let jsonData = stringBody.data(using: .utf8)
                        else {
                            return XCTFail("Did not receive a JSON body")
                    }
                    let decoder = JSONDecoder()
                    let body = try decoder.decode(MyLocal.self, from: jsonData)
                    XCTAssertEqual(body.id, "Mary")
                } catch {
                    XCTFail("No response body")
                }
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=Mary&password=qwerasdf")
            })
        }
    }
    
    func testGoodCredentialsRequest() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/captchalogin", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let stringBody = try response?.readString(),
                        let jsonData = stringBody.data(using: .utf8)
                        else {
                            return XCTFail("Did not receive a JSON body")
                    }
                    let decoder = JSONDecoder()
                    let body = try decoder.decode(MyLocal.self, from: jsonData)
                    XCTAssertEqual(body.id, "John")
                } catch {
                    XCTFail("No response body")
                }
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=John&password=12345&captcha=123456")
            })
        }
    }
    
    static func setupCodableRouter() -> Router {
        // "User accounts"
        let router = Router()
        MyLocal.registerLogin(router: router)
        CaptchaLocal.registerLogin(router: router)
        router.get("/private") { (authProfile: MyLocal, respondWith: (MyLocal?, RequestError?) -> Void) in
            respondWith(authProfile, nil)
        }
        
        router.post("/log-in") { (authProfile: MyLocal, form: MyForm, respondWith: (MyLocal?, RequestError?) -> Void) in
            respondWith(authProfile, nil)
        }
        
        router.get("/loggedin") { (profile: CaptchaLocal, respondWith: (CaptchaLocal? , RequestError?) -> Void) in
            respondWith(profile, nil)
        }
        return router
    }

}

private let users = ["John" : "12345", "Mary" : "qwerasdf"]

public struct MyLocal: TypeSafeLocal {
    public static var loginRoute: String = "/typesafelogin"
    
    public typealias inputForm = MyForm
    
    public static func verifyPassword(formData: MyForm, sessionId: String, callback: @escaping (MyLocal?) -> Void) {
        if (users[formData.username] == formData.password) {
            callback(MyLocal(sessionId: sessionId, id: formData.username))
        } else {
            callback(nil)
        }
    }
    
    public let sessionId: String
    
    public var id: String
    
    public static var store: Store?
    
    public static var sessionCookie: SessionCookie = SessionCookie(name: "hello", secret: "world")
    
}

public struct CaptchaLocal: TypeSafeLocal {
    
    public static var loginRoute: String = "/captchalogin"
    
    public static func verifyPassword(formData: MyForm, sessionId: String, callback: @escaping (CaptchaLocal?) -> Void) {
        if (users[formData.username] == formData.password && formData.captcha == "123456") {
            callback(CaptchaLocal(id: formData.username, sessionId: sessionId))
        } else {
            callback(nil)
        }
    }
    
    public typealias inputForm = MyForm
    
    public var id: String
    
    public static var store: Store?
    
    public static var sessionCookie: SessionCookie = SessionCookie(name: "hello", secret: "world")
    
    public var sessionId: String
    
    
}
    
public struct MyForm: Codable {
    let username: String
    let password: String
    let captcha: String?
}

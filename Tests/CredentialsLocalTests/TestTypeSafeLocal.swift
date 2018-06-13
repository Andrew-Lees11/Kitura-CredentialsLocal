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
            self.performRequest(method: "post", host: self.host, path: "/log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            })
        }
    }
    
    func testNoCredentialsRequest() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", host: self.host, path: "/request-log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            })
        }
    }
    
    func testBadCredentialsSimple() {
        // Good username, bad password
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=John&password=wrongPassword")
            })
        }
        
        
        // Good password, bad username
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/log-in", callback: {response in
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
            self.performRequest(method: "post", path:"/request-log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Content-Type": "application/x-www-form-urlencoded"], requestModifier: { request in
                request.write(from: "username=John&password=wrongPassword")
            })
        }
        
        
        // Good password, bad username
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path:"/log-in", callback: {response in
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
            self.performRequest(method: "post", path:"/log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    let body = try response?.readString()
                    XCTAssertEqual(body,"<!DOCTYPE html><html><body><b>Mary is logged in with Local</b></body></html>\n\n")
                }
                catch{
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
            self.performRequest(method: "post", path:"/log-in", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    let body = try response?.readString()
                    XCTAssertEqual(body,"<!DOCTYPE html><html><body><b>John is logged in with Local</b></body></html>\n\n")
                }
                catch{
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
        
        router.get("/private") { (authProfile: MyLocal, respondWith: (MyLocal?, RequestError?) -> Void) in
            respondWith(authProfile, nil)
        }
        
        router.post("/log-in") { (authProfile: MyLocal, respondWith: (MyLocal?, RequestError?) -> Void) in
            respondWith(authProfile, nil)
        }
        
        return router
    }

}

private let users = ["John" : "12345", "Mary" : "qwerasdf"]

public struct MyLocal: TypeSafeLocal {
    public typealias inputForm = MyForm
    
    public static func verifyPassword(formData: MyForm, sessionId: String, callback: @escaping (MyLocal?) -> Void) {
        if (users[formData.username] == formData.password && formData.captcha == "123456") {
            callback(MyLocal(sessionId: sessionId, id: formData.username))
        }
    }
    
    public let sessionId: String
    
    public var id: String
    
    public static var store: Store?
    
    public static var sessionCookie: SessionCookie = SessionCookie(name: "hello", secret: "world")
    
}

public struct MyForm: Codable {
    let username: String
    let password: String
    let captcha: String
}

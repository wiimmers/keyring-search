//
//  ContentView.swift
//  CredentialSniffer
//
//  Created by Nicholas Wimmers on 6/7/24.
//

import SwiftUI

struct ContentView: View {
    
    @State var query: String = ""
    @State var isFocused: Bool = false
    @State var results: String = ""
    
    var body: some View {
        VStack {
            Image(systemName: "dog")
                .imageScale(.large)
                .font(.system(size:75))
                .padding(.bottom, 5)
            
            Text("Credential Sniffer")
                .font(.system(size: 25))
                .fontWeight(.heavy)
                .fontDesign(.monospaced)
                .padding(.bottom, 10)
                
            TextField(
                "Search",
                text: $query,
                onEditingChanged: {
                    edit in self.isFocused = edit
                }
            )
            .textFieldStyle(SearchBarStyle(isFocused: $isFocused))
            .autocorrectionDisabled(true)
            
            DisplayResults(results: $results)
            
            Button("Search") {
                results = decodeError(query: query)
            }
        }
        .frame(width: 300)
        .padding()
        
        Spacer()
    }
}

struct SearchBarStyle: TextFieldStyle {
    
    @Binding var isFocused: Bool
    
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .frame(height: 40)
            .padding(5)
            .overlay(SchemeBehavior(isFocused: $isFocused))
            .font(.system(size: 20))
            .fontDesign(.monospaced)
    }
}

struct DisplayResults: View {
    
    @Binding var results: String
    
    var body: some View {
        if results.isEmpty {
            Text("\(results)")
                .frame(width: 0, height: 0)
                .padding(5)
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.gray, lineWidth: 0))
                .font(.system(size: 20))
                .fontDesign(.monospaced)
        } else {
            Text("\(results)")
                .frame(width: 300, height: 400)
                .padding(5)
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.gray, lineWidth: 0))
                .font(.system(size: 20))
                .fontDesign(.monospaced)
        }
    }
}

struct SchemeBehavior: View {
    
    @Binding var isFocused: Bool
    @Environment(\.colorScheme) var scheme
    
    var body: some View {
        
        if scheme == ColorScheme.dark {
            RoundedRectangle(cornerRadius: 5).stroke(isFocused ? Color.white : Color.gray, lineWidth: 2)
        } else {
            RoundedRectangle(cornerRadius: 5).stroke(isFocused ? Color.black : Color.gray, lineWidth: 2)
        }
    }
}

#Preview {
    ContentView()
}

func decodeError(query: String) -> String {
    do {
        let results = try SearchCredentials.search(by: "user", query: query)
        return "\(results)"
    } catch SnifferErrors.notfound {
        return "No results found"
    } catch {
        let e = SnifferErrors.unexpected
        return "Unexpected: \(e)"
    }
}

package com.spring.devMedical.payload.request;

public class GoogleLoginRequest {

    private String username;
    private String email;
    // private String password;
    private String imgUrl;
    private String displayName;
    private String role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getImgUrl() {
        return imgUrl;
    }

    public void setImgUrl(String imgUrl) {
        this.imgUrl = imgUrl;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    /*
     * public String getPassword() { return password; }
     */

    /*
     * public void setPassword(String password) { this.password = password; }
     */

}
const baseUrl = pm.collectionVariables.get("baseUrl");
const authUrl = pm.variables.replaceIn(baseUrl) + "/auth";
const unauthRequest = {
    url: authUrl + "/unauthorized",
    method: "GET",
    header: {"Authorization": "Bearer " + pm.environment.get("token")}
};
pm.sendRequest(unauthRequest, function (err, response) {
    if (response.code !== 401)
        return;     // existing token is still good
    const reply = response.json();
    const user = pm.environment.get("user");
    const str1 = user + ":" + reply.rlm + ":" + pm.environment.get("password");
    const ha1 = CryptoJS.MD5(str1).toString();
    const clientNonce = pm.variables.replaceIn("{{$randomUUID}}");
    const str2 = ha1 + ":" + reply.nnc + ":" + clientNonce;
    const ha2 = CryptoJS.MD5(str2).toString();
    const loginRequest = {
        url: authUrl + "/login",
        method: "POST",
        header: {"Content-Type": "application/json"},
        body: {
            mode: "raw",
            raw: JSON.stringify(
		{
		    rlm: reply.rlm,
		    usr: user,
		    nnc: reply.nnc,
		    cnnc: clientNonce,
		    hash: ha2
		}
	    )
        }
    };
    pm.sendRequest(loginRequest, (err, response) => {
        const loginReply = response.json();
        pm.environment.set("token", loginReply.jwt);
    })
});

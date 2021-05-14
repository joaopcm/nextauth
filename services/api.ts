import axios, { AxiosError } from "axios";
import { parseCookies, setCookie } from "nookies";
import { signOut } from "../contexts/AuthContext";
import { AuthError } from "../errors/AuthError";

let isRefreshing = false;
let failedRequestsQueue = [];

export function setupAPIClient(context = undefined) {
  let cookies = parseCookies(context);

  const api = axios.create({
    baseURL: "http://localhost:3333",
    headers: {
      Authorization: `Bearer ${cookies["nextauth.token"]}`,
    },
  });

  api.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      if (error.response.status === 401) {
        if (error.response.data?.code === "token.expired") {
          cookies = parseCookies(context);

          const { "nextauth.refreshToken": refreshToken } = cookies;
          const originalConfig = error.config;

          if (!isRefreshing) {
            isRefreshing = true;

            api
              .post("refresh", {
                refreshToken,
              })
              .then((response) => {
                const { token } = response.data;
                const cookieOptions = {
                  maxAge: 60 * 60 * 24 * 30, // 30 days
                  path: "/",
                };

                setCookie(context, "nextauth.token", token, cookieOptions);
                setCookie(
                  context,
                  "nextauth.refreshToken",
                  response.data.refreshToken,
                  cookieOptions
                );

                api.defaults.headers["Authorization"] = `Bearer ${token}`;

                failedRequestsQueue.forEach((request) =>
                  request.resolve(token)
                );
              })
              .catch((err) => {
                failedRequestsQueue.forEach((request) => request.reject(err));

                if (process.browser) {
                  signOut();
                }
              })
              .finally(() => {
                failedRequestsQueue = [];
                isRefreshing = false;
              });
          }

          return new Promise((resolve, reject) => {
            failedRequestsQueue.push({
              resolve: (token: string) => {
                originalConfig.headers["Authorization"] = `Bearer ${token}`;

                resolve(api(originalConfig));
              },
              reject: (err: AxiosError) => {
                reject(err);
              },
            });
          });
        } else {
          if (process.browser) {
            signOut();
          } else {
            return Promise.reject(new AuthError());
          }
        }
      }

      return Promise.reject(error);
    }
  );

  return api;
}

export interface TodoItem {
  id: string
  title: string
  description: string
  done: boolean
  image_data_url?: string
  image_content_type?: string
  created_at: string
  updated_at: string
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface LoginResponse {
  userID?: string
  user_id?: string
  username?: string
  baseURL?: string
  bootstrapPath?: string
  handshakePath?: string
  csrfCookieName?: string
  csrfHeaderName?: string
  csrfToken?: string
  accessToken?: string
  refreshToken?: string
}

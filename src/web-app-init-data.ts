
/**
 * @{link https://core.telegram.org/bots/webapps#webappinitdata}
 */
export interface WebAppInitData {
  queryId?: string;
  user?: WebAppUser;
  receiver?: WebAppUser;
  chat?: WebAppChat;
  startParam?: string;
  canSendAfter?: Date;
  authDate: Date;
  hash: string;
}

/**
 * @{link https://core.telegram.org/bots/webapps#webappuser}
 */
export interface WebAppUser {
  id: number;
  isBot?: boolean;
  firstName: string;
  lastName?: string;
  username?: string;
  languageCode?: string;
  isPremium?: boolean;
  photoUrl?: string;
}

/**
 * @{link https://core.telegram.org/bots/webapps#webappchat}
 */
export interface WebAppChat {
  id: number;
  type: ('group' | 'supergroup' | 'channel');
  title: string;
  username?: string;
  photoUrl?: string;
}

type RawData = Record<string, any>;


/**
 * Parses web application initialization data received
 * from Telegram. Make sure to validate it first!
 *
 * @param initData - init data as string or URLSearchParams.
 */
export function parseWebAppInitData(
  initData: (string | URLSearchParams)

): WebAppInitData {

  const initDataParams = (
    (typeof initData === 'string') ? new URLSearchParams(initData) :
    (initData instanceof URLSearchParams) ? initData :
    undefined
  );

  if (!initDataParams) {
    throw new Error(
      `Init data must be either a string ` +
      `or a URLSearchParams instance`
    );
  }

  const rawData: RawData = {};
  for (const [key, value] of initDataParams) {
    rawData[key] = value;
  }

  return <WebAppInitData> {
    queryId: rawData['query_id'],
    user: parseWebAppUser(
      fromJson(rawData['user'])
    ),
    receiver: parseWebAppUser(
      fromJson(rawData['receiver'])
    ),
    chat: parseWebAppChat(
      fromJson(rawData['chat'])
    ),
    startParam: rawData['start_param'],
    canSendAfter: parseDate(rawData['can_send_after']),
    authDate: parseDate(rawData['auth_date']),
    hash: rawData['hash'],
  };

}


function fromJson(maybeJson: (string | undefined)): RawData {
  return (maybeJson ? JSON.parse(maybeJson) : undefined);
}

function parseWebAppUser(
  rawData: (RawData | undefined)

): (WebAppUser | undefined) {

  return (rawData ? {
    id: rawData['id'],
    isBot: rawData['is_bot'],
    firstName: rawData['first_name'],
    lastName: rawData['last_name'],
    username: rawData['username'],
    languageCode: rawData['language_code'],
    isPremium: rawData['is_premium'],
    photoUrl: rawData['photo_url'],

  } : undefined);

}

function parseWebAppChat(
  rawData: (RawData | undefined)

): (WebAppChat | undefined) {

  return (rawData ? {
    id: rawData['id'],
    type: rawData['type'],
    title: rawData['title'],
    username: rawData['username'],
    photoUrl: rawData['photoUrl'],

  } : undefined);

}

function parseDate(
  rawDate: (string | undefined)

): (Date | undefined) {

  return (rawDate
    ? new Date(parseInt(rawDate, 10) * 1_000)
    : undefined
  );

}

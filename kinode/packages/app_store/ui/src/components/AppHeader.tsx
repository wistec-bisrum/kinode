import React from "react";
import { AppInfo } from "../types/Apps";
import { appId } from "../utils/app";
import { useNavigate } from "react-router-dom";
import classNames from "classnames";

interface AppHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  app: AppInfo;
  size?: "small" | "medium" | "large";
}

export default function AppHeader({
  app,
  size = "medium",
  ...props
}: AppHeaderProps) {
  const navigate = useNavigate()

  return (
    <div
      {...props}
      className={classNames('flex w-full justify-content-start', size, props.className, { 'cursor-pointer': size !== 'large' })}
      onClick={() => navigate(`/app-details/${appId(app)}`)}
    >
      <img
        src={
          app.metadata?.image ||
          "https://png.pngtree.com/png-vector/20190215/ourmid/pngtree-vector-question-mark-icon-png-image_515448.jpg"
        }
        alt="app icon"
        className={classNames('mr-2', { 'h-32 rounded-md': size === 'large', 'h-12 rounded': size !== 'large' })}
      />
      <div className="flex flex-col w-full">
        <div
          className={classNames("whitespace-nowrap overflow-hidden text-ellipsis", { 'text-3xl': size === 'large', })}
        >
          {app.metadata?.name || appId(app)}
        </div>
        {app.metadata?.description && size !== "large" && (
          <div className="whitespace-nowrap overflow-hidden text-ellipsis">
            {app.metadata?.description?.slice(0, 100)}
          </div>
        )}
      </div>
    </div>
  );
}
